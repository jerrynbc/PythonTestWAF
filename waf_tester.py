#!/usr/bin/env python3
"""
python_test_waf
用于测试 WAF 是否能够正确拦截黑样本，并允许白样本通过
"""

import os
import sys
# 禁用输出缓冲，确保print输出能够实时显示
sys.stdout.reconfigure(line_buffering=True)
import argparse
import requests
import csv
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict
import time
from datetime import datetime


def parse_http_request(content: str) -> Tuple[str, Dict[str, str], str]:
    """
    解析 HTTP 请求文件，返回方法、URL、headers、body
    
    Returns:
        (method_url, headers_dict, body)
    """
    lines = content.strip().split('\n')
    
    # 第一行是请求行：METHOD /path HTTP/1.1
    request_line = lines[0]
    
    # 解析 headers
    headers = {}
    body = ''
    in_body = False
    
    for line in lines[1:]:
        if in_body:
            body += line + '\n'
        elif line.strip() == '':
            in_body = True
        else:
            # 解析 header: key: value
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
    
    # 移除 body 末尾的换行
    body = body.rstrip()
    
    return request_line, headers, body

def send_request(request_line: str, headers: Dict[str, str], body: str, target_host: str = None, protocol: str = 'http', packet_loss_rate: float = 0.0, max_retries: int = 3, debug: bool = False, timeout: Tuple[float, float] = (10, 30)) -> Tuple[int, str, str, bool]:
    """
    发送 HTTP 请求并返回状态码、响应和 RST 检测结果
    
    Args:
        request_line: 请求行
        headers: HTTP headers
        body: 请求体
        target_host: 靶机地址（可选，格式：host:port）
        protocol: 协议（http 或 https）
        packet_loss_rate: 丢包率（0.0-1.0，默认：0.0）
        max_retries: 最大重传次数（默认：3）
        debug: 是否启用调试输出（默认：False）
        timeout: 超时设置（连接超时, 读取超时），默认：(10, 30)秒
    
    Returns:
        (status_code, reason, response_body, is_rst_detected)
    """
    import random
    
    # 解析请求行
    parts = request_line.split()
    if len(parts) < 2:
        return 0, "Invalid request line"
    
    method = parts[0]
    url_path = parts[1]
    
    # 从 headers 获取 host
    host_in_header = headers.get('Host', headers.get('host', ''))
    
    # 确定实际发送请求的 host
    if target_host:
        # 如果指定了靶机地址，使用它
        host_for_url = target_host
    else:
        # 否则使用 Host header 中的地址
        if not host_in_header:
            return 0, "No Host header found and no target specified"
        host_for_url = host_in_header
    
    # 构建完整的 URL
    url = f"{protocol}://{host_for_url}{url_path}"
    
    # 移除一些会自动处理的 headers
    headers_to_send = headers.copy()
    headers_to_send.pop('Content-Length', None)
    headers_to_send.pop('content-length', None)
    
    # 判断是否是大包，并根据大小调整 timeout
    content_length = 0
    if body:
        content_length = len(body.encode('utf-8'))
        headers_to_send['Content-Length'] = str(content_length)
    
    # 使用传入的超时参数，不再根据内容长度动态调整
    # 如需不同的超时设置，可以通过函数参数进行配置
    
    # 重试逻辑
    for attempt in range(max_retries):
        # 模拟丢包
        if packet_loss_rate > 0 and random.random() < packet_loss_rate:
            # 丢包，等待后重试
            if debug:
                print(f"[调试] 尝试 {attempt+1}/{max_retries}: 模拟丢包，等待 1 秒后重试")
            time.sleep(1)  # 等待 1 秒后重试
            continue
        
        try:
            # 使用通用的 request 方法，统一处理所有方法
            # data 参数在 body 存在时会被自动编码和发送
            if debug:
                print(f"[调试] 尝试 {attempt+1}/{max_retries}: 发送请求 - {method} {url}")
                print(f"[调试] 请求头: {headers_to_send}")
                print(f"[调试] 请求体大小: {content_length} 字节")
            
            response = requests.request(
                method=method,
                url=url,
                headers=headers_to_send,
                data=body if body else None,
                timeout=timeout,
                stream=False  # 不要流式传输
            )
            
            response_body = response.text
            
            if debug:
                print(f"[调试] 响应: {response.status_code} {response.reason}")
                print(f"[调试] 响应体大小: {len(response_body)} 字节")
            
            return response.status_code, response.reason, response_body, False
            
        except requests.exceptions.Timeout:
            if debug:
                print(f"[调试] 尝试 {attempt+1}/{max_retries}: 超时，等待 1 秒后重试")
            if attempt < max_retries - 1:
                time.sleep(1)  # 重试前等待 1 秒
                continue
            else:
                return 0, f"Timeout (tried {max_retries} times, {content_length} bytes)", "", False
        except requests.exceptions.ConnectionError as e:
            is_rst = "Connection reset by peer" in str(e) or "ECONNRESET" in str(e)
            if debug:
                if is_rst:
                    print(f"[调试] 尝试 {attempt+1}/{max_retries}: 检测到 RST 拦截 - {str(e)}，等待 1 秒后重试")
                else:
                    print(f"[调试] 尝试 {attempt+1}/{max_retries}: 连接错误 - {str(e)}，等待 1 秒后重试")
            if attempt < max_retries - 1:
                time.sleep(1)  # 连接错误也重试
                continue
            else:
                return 0, f"Connection Error: {str(e)}", "", is_rst
        except Exception as e:
            if debug:
                print(f"[调试] 尝试 {attempt+1}/{max_retries}: 其他错误 - {str(e)}，等待 1 秒后重试")
            if attempt < max_retries - 1:
                time.sleep(1)  # 其他错误也重试
                continue
            else:
                return 0, f"Error: {str(e)}", "", False
    
    return 0, f"All {max_retries} attempts failed", "", False


def test_file_content(content: str, is_black: bool, target_host: str = None, protocol: str = 'http', packet_loss_rate: float = 0.0, max_retries: int = 3, debug: bool = False, custom_code: int = 403, rst_detect: bool = False, keyword: str = None, timeout: Tuple[float, float] = (10, 30)) -> Tuple[str, bool, int, str, str, str]:
    """
    测试文件内容
    
    Args:
        content: 文件内容
        is_black: 是否为黑样本
        target_host: 靶机地址（可选）
        protocol: 协议（http 或 https）
        packet_loss_rate: 丢包率（0.0-1.0，默认：0.0）
        max_retries: 最大重传次数（默认：3）
        debug: 是否启用调试输出（默认：False）
        custom_code: 自定义 WAF 拦截状态码（默认：403）
        rst_detect: 是否检测 RST 拦截（默认：False）
        keyword: 响应 body 中的关键字，用于判断 WAF 拦截（默认：None）
        timeout: 超时设置（连接超时, 读取超时），默认：(10, 30)秒
    
    Returns:
        (文件名, 是否符合预期, 状态码, 响应信息, 样本类型, 完整路径)
    """
    # 解析请求
    request_line, headers, body = parse_http_request(content)
    
    # 发送请求
    status_code, reason, response_body, is_rst_detected = send_request(request_line, headers, body, target_host, protocol, packet_loss_rate, max_retries, debug, timeout)
    
    # 判断是否符合预期
    expected_blocked = is_black
    actually_blocked = False
    
    # 1. 检查状态码拦截（默认或自定义）
    if status_code == custom_code:
        actually_blocked = True
    # 2. 检查 RST 拦截（如果启用）
    if rst_detect and is_rst_detected:
        actually_blocked = True
    # 3. 检查响应 body 和响应原因中的关键字，用于判断 WAF 拦截（如果指定了关键字）
    if keyword:
        # 同时检查响应体和响应原因短语
        if keyword in response_body or keyword in reason:
            actually_blocked = True
    
    is_correct = (expected_blocked == actually_blocked)
    
    sample_type = "黑样本" if is_black else "白样本"
    
    return "", is_correct, status_code, reason, sample_type, content


def test_file_wrapper(args: Tuple[Path, bool, str, str, float, int, bool, int, bool, str, Tuple[float, float]]) -> Dict:
    """
    包装函数，用于并发调用
    
    Args:
        args: (file_path, is_black, target_host, protocol, packet_loss_rate, max_retries, debug, custom_code, rst_detect, keyword, timeout)
    
    Returns:
        结果字典
    """
    file_path, is_black, target_host, protocol, packet_loss_rate, max_retries, debug, custom_code, rst_detect, keyword, timeout = args
    
    try:
        # 读取文件内容
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # 测试
        _, is_correct, status_code, reason, sample_type, _ = test_file_content(content, is_black, target_host, protocol, packet_loss_rate, max_retries, debug, custom_code, rst_detect, keyword, timeout)
        
        return {
            'file': file_path.name,
            'file_path': str(file_path),
            'type': sample_type,
            'is_correct': is_correct,
            'status_code': status_code,
            'reason': reason,
            'expected_blocked': is_black,
            'content': content
        }
    except Exception as e:
        return {
            'file': file_path.name,
            'file_path': str(file_path),
            'type': "黑样本" if is_black else "白样本",
            'is_correct': False,
            'status_code': 0,
            'reason': f"错误: {str(e)}",
            'expected_blocked': is_black,
            'content': ""
        }


def save_to_csv(results: List[Dict], output_file: str):
    """保存结果到 CSV 文件"""
    with open(output_file, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.writer(f)
        writer.writerow(['文件名', '样本类型', '期望行为', '状态码', '响应信息', '是否符合预期'])
        
        for r in results:
            expected = "应被拦截" if r['expected_blocked'] else "不应被拦截"
            status = f"{r['status_code']}" if r['status_code'] else r['reason']
            result = "是" if r['is_correct'] else "否"
            writer.writerow([r['file'], r['type'], expected, status, r['reason'], result])


def copy_samples_to_directories(results: List[Dict], base_dir: str):
    """根据结果将样本复制到对应目录"""
    base_path = Path(base_dir)
    
    # 创建主目录
    base_path.mkdir(exist_ok=True)
    
    # 创建分类目录
    correct_dir = base_path / "符合预期"
    incorrect_dir = base_path / "不符合预期"
    
    correct_dir.mkdir(exist_ok=True)
    incorrect_dir.mkdir(exist_ok=True)
    
    correct_count = 0
    incorrect_count = 0
    
    for r in results:
        source_path = Path(r['file_path'])
        
        if r['is_correct']:
            dest_path = correct_dir / source_path.name
            correct_count += 1
        else:
            dest_path = incorrect_dir / source_path.name
            incorrect_count += 1
        
        # 复制文件
        if source_path.exists():
            shutil.copy2(source_path, dest_path)
    
    return correct_count, incorrect_count


def test_directory(directory: str, delay: float = 0.1, output_file: str = None, target_host: str = None, 
                   threads: int = 10, output_dir: str = None, auto_create_dir: bool = True, protocol: str = 'http',
                   packet_loss_rate: float = 0.0, max_retries: int = 3, debug: bool = False,
                   custom_code: int = 403, rst_detect: bool = False, keyword: str = None, timeout: Tuple[float, float] = (10, 30)):
    """
    测试目录中的所有样本文件
    
    Args:
        directory: 样本目录
        delay: 请求间隔（秒，不用于并发模式）
        output_file: 输出文件路径（可选，只有明确指定时才输出 CSV）
        target_host: 靶机地址（可选，格式：host:port）
        threads: 并发线程数
        output_dir: 输出目录（用于分类存储样本，只有明确指定时才使用）
        auto_create_dir: 不再使用，保留为兼容性
        protocol: 协议（http 或 https）
        packet_loss_rate: 丢包率（0.0-1.0，默认：0.0）
        max_retries: 最大重传次数（默认：3）
        debug: 是否启用调试输出（默认：False）
        custom_code: 自定义 WAF 拦截状态码（默认：403）
        rst_detect: 是否检测 RST 拦截（默认：False）
        keyword: 响应 body 中的关键字，用于判断 WAF 拦截（默认：None）
    """
    dir_path = Path(directory)
    
    # 不再自动创建结果目录，只有明确指定了 output_dir 才使用
    
    if not dir_path.exists():
        print(f"错误: 目录不存在: {directory}")
        return
    
    # 收集所有样本文件
    black_files = sorted(dir_path.glob('*.black'))
    white_files = sorted(dir_path.glob('*.white'))
    
    all_files = []
    for f in black_files:
        all_files.append((f, True))  # (file_path, is_black)
    for f in white_files:
        all_files.append((f, False))  # (file_path, is_black)
    
    print(f"找到 {len(black_files)} 个黑样本，{len(white_files)} 个白样本")
    print(f"总共 {len(all_files)} 个样本")
    if target_host:
        print(f"靶机地址: {protocol}://{target_host}")
    print(f"并发线程数: {threads}")
    if output_dir:
        print(f"结果目录: {output_dir}")
    print(f"开始测试...\n")
    
    start_time = time.time()
    results = []
    correct_count = 0
    total_count = len(all_files)
    
    # 准备并发任务参数
    tasks = [(file_path, is_black, target_host, protocol, packet_loss_rate, max_retries, debug, custom_code, rst_detect, keyword, timeout) for file_path, is_black in all_files]
    
    # 使用线程池并发执行
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(test_file_wrapper, task): idx for idx, task in enumerate(tasks)}
        
        completed = 0
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            results.append(result)
            
            # 显示进度
            sample_type = result['type']
            expected_blocked = "应被拦截" if result['expected_blocked'] else "不应被拦截"
            actual_status = f"{result['status_code']} ({result['reason']})" if result['status_code'] else f"错误: {result['reason']}"
            
            if result['is_correct']:
                result_msg = "✓ 符合预期"
                correct_count += 1
            else:
                result_msg = "✗ 不符合预期"
            
            print(f"[{completed}/{total_count}] {result['file']} ({sample_type}) - {result_msg} - {actual_status}")
    
    elapsed_time = time.time() - start_time
    
    # 输出统计信息
    print("\n" + "=" * 60)
    print("测试完成！")
    print(f"总样本数: {total_count}")
    print(f"符合预期: {correct_count} ({correct_count/total_count*100:.1f}%)")
    print(f"不符合预期: {total_count - correct_count} ({(total_count-correct_count)/total_count*100:.1f}%)")
    print(f"总耗时: {elapsed_time:.2f} 秒")
    print(f"平均速度: {total_count/elapsed_time:.2f} 样本/秒")
    print("=" * 60)
    
    # 只有当明确指定了 output_file 时，才输出 CSV 文件
    if output_file:
        save_to_csv(results, output_file)
        print(f"\nCSV 结果已保存到: {output_file}")
    
    # 只有当明确指定了 output_dir 时，才分类复制样本
    if output_dir:
        correct_count, incorrect_count = copy_samples_to_directories(results, output_dir)
        print(f"\n样本分类完成:")
        print(f"  符合预期: {correct_count} 个样本 -> {output_dir}/符合预期/")
        print(f"  不符合预期: {incorrect_count} 个样本 -> {output_dir}/不符合预期/")
    
    # 显示不符合预期的样本
    incorrect_samples = [r for r in results if not r['is_correct']]
    if incorrect_samples:
        print("\n不符合预期的样本:")
        print("-" * 60)
        for r in incorrect_samples:
            status = f"{r['status_code']}" if r['status_code'] else r['reason']
            if r['expected_blocked']:
                print(f"✗ {r['file']} (黑样本，应被拦截但返回 {status})")
            else:
                print(f"✗ {r['file']} (白样本，不应被拦截但返回 403)")


def parse_target_url(target: str) -> Tuple[str, int]:
    """
    解析目标 URL，提取协议、主机和端口
    
    Args:
        target: URL 字符串，如 http://127.0.0.1 或 https://example.com:8443
    
    Returns:
        (host:port, protocol) 或 (host, port)
    """
    import re
    from urllib.parse import urlparse
    
    if not target:
        return None, None
    
    # 去除前后空格
    target = target.strip()
    
    # 如果没有协议前缀，添加 http://
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    
    # 解析 URL
    parsed = urlparse(target)
    host = parsed.hostname
    port = parsed.port
    
    # 如果没有指定端口，根据协议设置默认端口
    if port is None:
        if parsed.scheme == 'https':
            port = 443
        else:
            port = 80
    
    # 返回 host:port 格式
    return f"{host}:{port}", parsed.scheme


def main():
    parser = argparse.ArgumentParser(description='WAF 测试工具')
    parser.add_argument('-d', '--directory', type=str, default='1',
                       help='测试样本目录 (默认: 1)')
    parser.add_argument('-o', '--output', type=str, default=None,
                       help='输出 CSV 文件路径 (可选)')
    parser.add_argument('-t', '--target', type=str, default=None,
                       help='靶机地址，支持完整 URL：http://127.0.0.1 或 https://127.0.0.1:8443')
    parser.add_argument('-n', '--threads', type=int, default=10,
                       help='并发线程数 (默认: 10)')
    parser.add_argument('-s', '--split', type=str, default=None,
                       help='输出目录，用于分类存储样本（可选，默认自动创建）')
    parser.add_argument('--no-auto-dir', action='store_true',
                       help='不自动创建结果目录')
    parser.add_argument('--loss-rate', type=float, default=0.0,
                       help='模拟丢包率 (0.0-1.0，默认: 0.0)')
    parser.add_argument('--max-retries', type=int, default=3,
                       help='最大重传次数 (默认: 3)')
    parser.add_argument('--timeout', type=str, default='10,30',
                       help='超时设置，格式: 连接超时,读取超时（秒，默认: 10,30）')
    parser.add_argument('--debug', action='store_true',
                       help='启用调试输出 (默认: 禁用)')
    parser.add_argument('-C', '--custom-code', type=int, default=403,
                       help='自定义 WAF 拦截状态码 (默认: 403)')
    parser.add_argument('-R', '--rst-detect', action='store_true',
                       help='检测 RST 拦截 (默认: 禁用)')
    parser.add_argument('-K', '--keyword', type=str, default=None,
                       help='响应 body 中的关键字，用于判断 WAF 拦截 (默认: 无)')
    
    args = parser.parse_args()
    
    auto_create = not args.no_auto_dir
    
    # 解析 target URL
    target_host = None
    protocol = 'http'
    if args.target:
        target_host, protocol = parse_target_url(args.target)
    else:
        # 如果没有提供靶机地址，输出帮助菜单并退出
        print("错误: 必须提供靶机地址 (-t/--target)")
        parser.print_help()
        sys.exit(1)
    
    # 只有明确指定了 --output 参数时，才输出 CSV 文件
    output_file = args.output
    
    # 只有明确指定了 --split 参数时，才使用 output_dir
    output_dir = args.split
    
    # WAF 拦截判断参数
    custom_code = args.custom_code
    rst_detect = args.rst_detect
    keyword = args.keyword
    
    # 超时参数解析
    try:
        timeout_parts = args.timeout.split(',')
        if len(timeout_parts) == 1:
            # 如果只提供一个值，同时作为连接超时和读取超时
            connect_timeout = read_timeout = float(timeout_parts[0].strip())
        else:
            # 否则分别解析连接超时和读取超时
            connect_timeout = float(timeout_parts[0].strip())
            read_timeout = float(timeout_parts[1].strip())
        timeout = (connect_timeout, read_timeout)
    except (ValueError, IndexError):
        # 解析失败，使用默认值
        timeout = (10.0, 30.0)
    
    # delay 参数已废弃，因为并发模式下不生效，但为兼容性保留
    test_directory(args.directory, delay=0.1, output_file=output_file, target_host=target_host, 
                   threads=args.threads, output_dir=output_dir, auto_create_dir=auto_create, protocol=protocol,
                   packet_loss_rate=args.loss_rate, max_retries=args.max_retries, debug=args.debug,
                   custom_code=custom_code, rst_detect=rst_detect, keyword=keyword, timeout=timeout)


if __name__ == '__main__':
    main()
