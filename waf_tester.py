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
import csv
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict
import time


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
    使用 socket 直接发送原始 HTTP 请求，支持自定义 HTTP 版本号
    
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
    import socket
    import ssl
    
    # 解析请求行，保留完整的 HTTP 版本号
    parts = request_line.split()
    if len(parts) < 2:
        return 0, "Invalid request line", "", False
    
    method = parts[0]
    url_path = parts[1]
    # 保留原始的 HTTP 版本号，如果有的话
    http_version = parts[2] if len(parts) >= 3 else "HTTP/1.1"
    
    # 从 headers 获取 host
    host_in_header = headers.get('Host', headers.get('host', ''))
    
    # 确定实际发送请求的 host 和 port
    if target_host:
        # 如果指定了靶机地址，使用它
        if ':' in target_host:
            host, port_str = target_host.split(':', 1)
            port = int(port_str)
        else:
            host = target_host
            port = 443 if protocol == 'https' else 80
    else:
        # 否则使用 Host header 中的地址
        if not host_in_header:
            return 0, "No Host header found and no target specified", "", False
        if ':' in host_in_header:
            host, port_str = host_in_header.split(':', 1)
            port = int(port_str)
        else:
            host = host_in_header
            port = 443 if protocol == 'https' else 80
    
    # 构建完整的原始 HTTP 请求
    # 1. 请求行
    full_request = f"{method} {url_path} {http_version}\r\n"
    
    # 2. 构建 headers
    headers_to_send = headers.copy()
    
    # 如果没有 Content-Length，自动添加
    if 'Content-Length' not in headers_to_send and 'content-length' not in headers_to_send:
        content_length = len(body.encode('utf-8')) if body else 0
        headers_to_send['Content-Length'] = str(content_length)
    
    # 添加所有 headers
    for key, value in headers_to_send.items():
        full_request += f"{key}: {value}\r\n"
    
    # 添加空行分隔 headers 和 body
    full_request += "\r\n"
    
    # 添加请求体
    if body:
        full_request += body
    
    if debug:
        print(f"[调试] 原始请求:\n{full_request}")
    
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
            # 创建 socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout[0])  # 连接超时
            
            # 连接到服务器
            sock.connect((host, port))
            
            # 如果是 https，包装成 ssl socket
            if protocol == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            
            # 设置读取超时
            sock.settimeout(timeout[1])
            
            # 发送请求
            sock.sendall(full_request.encode('utf-8'))
            
            # 接收响应
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    # 超时，停止接收
                    break
            
            # 关闭连接
            sock.close()
            
            # 解析响应
            response_str = response.decode('utf-8', errors='ignore')
            
            if debug:
                print(f"[调试] 原始响应:\n{response_str}")
            
            # 解析状态行
            status_line = response_str.split('\r\n')[0]
            status_parts = status_line.split()
            
            if len(status_parts) < 2:
                return 0, "Invalid response status line", response_str, False
            
            status_code = int(status_parts[1])
            reason = ' '.join(status_parts[2:]) if len(status_parts) > 2 else ""
            
            return status_code, reason, response_str, False
            
        except socket.timeout:
            if debug:
                print(f"[调试] 尝试 {attempt+1}/{max_retries}: 超时，等待 1 秒后重试")
            if attempt < max_retries - 1:
                time.sleep(1)  # 重试前等待 1 秒
                continue
            else:
                return 0, f"Timeout (tried {max_retries} times)", "", False
        except ConnectionResetError:
            # 检测到 RST 重置
            if debug:
                print(f"[调试] 尝试 {attempt+1}/{max_retries}: 检测到 RST 拦截，等待 1 秒后重试")
            if attempt < max_retries - 1:
                time.sleep(1)  # 连接错误也重试
                continue
            else:
                return 0, "Connection Reset by Peer", "", True
        except Exception as e:
            if debug:
                print(f"[调试] 尝试 {attempt+1}/{max_retries}: 错误 - {str(e)}，等待 1 秒后重试")
            if attempt < max_retries - 1:
                time.sleep(1)  # 其他错误也重试
                continue
            else:
                error_msg = "Connection Error" if not debug else f"Connection Error: {str(e)}"
                return 0, error_msg, "", False
    
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
        # 判断是否是网络相关错误
        error_str = str(e)
        is_network_error = "ConnectionError" in error_str or "Connection error" in error_str.lower() or "Failed to establish a new connection" in error_str
        
        # 根据debug参数决定错误信息的详细程度
        if is_network_error and not debug:
            error_msg = "Connection Error"
        else:
            error_msg = f"错误: {error_str}"
            
        return {
            'file': file_path.name,
            'file_path': str(file_path),
            'type': "黑样本" if is_black else "白样本",
            'is_correct': False,
            'status_code': 0,
            'reason': error_msg,
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
            
            # 更新进度计数
            if result['is_correct']:
                correct_count += 1
            
            # 显示进度
            if debug:
                # debug模式下显示详细信息
                sample_type = result['type']
                expected_blocked = "应被拦截" if result['expected_blocked'] else "不应被拦截"
                actual_status = f"{result['status_code']} ({result['reason']})" if result['status_code'] else f"错误: {result['reason']}"
                
                if result['is_correct']:
                    result_msg = "✓ 符合预期"
                else:
                    result_msg = "✗ 不符合预期"
                
                print(f"[{completed}/{total_count}] {result['file']} ({sample_type}) - {result_msg} - {actual_status}")
            else:
                # 非debug模式下显示进度条
                # 使用固定长度的进度条，确保跨平台一致性
                progress = completed / total_count
                bar_width = 50
                filled_width = int(bar_width * progress)
                empty_width = bar_width - filled_width
                
                # 使用█作为填充字符，-作为空字符
                progress_bar = "█" * filled_width + "-" * empty_width
                
                # 格式化进度信息
                percentage = f"{(progress * 100):6.1f}%"  # 固定宽度6字符，确保对齐
                count_info = f"({completed:4d}/{total_count:4d})"  # 固定宽度，确保对齐
                
                # 使用sys.stdout.write和flush确保跨平台兼容性和实时更新
                # 使用\r回到行首，并用空格清除可能的残留字符
                sys.stdout.write(f"\r测试中: [{progress_bar}] {percentage} {count_info}")
                sys.stdout.flush()
        
        # 测试结束后换行
        if not debug:
            print()
    
    elapsed_time = time.time() - start_time
    
    # 计算拦截率和误报率
    black_total = sum(1 for r in results if r['expected_blocked'])
    white_total = sum(1 for r in results if not r['expected_blocked'])
    
    # 黑样本被正确拦截的数量
    black_blocked_correctly = sum(1 for r in results if r['expected_blocked'] and r['is_correct'])
    
    # 白样本被错误拦截的数量
    white_blocked_incorrectly = sum(1 for r in results if not r['expected_blocked'] and not r['is_correct'])
    
    # 计算拦截率和误报率
    detection_rate = black_blocked_correctly / black_total * 100 if black_total > 0 else 0
    false_positive_rate = white_blocked_incorrectly / white_total * 100 if white_total > 0 else 0
    
    # 只有当使用了--output或--split参数时，才显示不符合预期的样本
    if output_file or output_dir:
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
    
    # 输出统计信息
    print("\n" + "=" * 60)
    print("测试完成！")
    print(f"总样本数: {total_count}")
    print(f"符合预期: {correct_count} ({correct_count/total_count*100:.1f}%)")
    print(f"不符合预期: {total_count - correct_count} ({(total_count-correct_count)/total_count*100:.1f}%)")
    print(f"拦截率: {detection_rate:.1f}% ({black_blocked_correctly}/{black_total} 黑样本被正确拦截)")
    print(f"误报率: {false_positive_rate:.1f}% ({white_blocked_incorrectly}/{white_total} 白样本被错误拦截)")
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
