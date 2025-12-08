#!/usr/bin/env python3
"""
python_test_waf WebUI
基于 Flask 框架实现的图形化交互界面
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import sys
import subprocess
import threading
import time
import queue

app = Flask(__name__)

# 测试结果队列
result_queue = queue.Queue()
# 测试状态
is_testing = False
# 当前测试进程
current_process = None
# 测试日志
test_logs = []

# 支持的样本目录列表 - 包含有.black或.white文件的目录，支持2级目录

def get_valid_sample_dirs():
    """获取有效的样本目录，支持2级目录，只有包含.black或.white文件的目录才会被识别"""
    valid_dirs = []
    
    # 检查1级目录
    for d in os.listdir('.'):
        dir_path = os.path.join('.', d)
        if os.path.isdir(dir_path) and d != '__pycache__':
            # 检查目录中是否存在以.black或.white结尾的文件
            has_black = False
            has_white = False
            try:
                for f in os.listdir(dir_path):
                    if f.endswith('.black'):
                        has_black = True
                    elif f.endswith('.white'):
                        has_white = True
                    if has_black and has_white:
                        break
            except PermissionError:
                # 跳过没有权限访问的目录
                continue
            
            if has_black or has_white:
                valid_dirs.append(d)
            else:
                # 检查2级目录
                for sub_d in os.listdir(dir_path):
                    sub_dir_path = os.path.join(dir_path, sub_d)
                    if os.path.isdir(sub_dir_path):
                        sub_has_black = False
                        sub_has_white = False
                        try:
                            for f in os.listdir(sub_dir_path):
                                if f.endswith('.black'):
                                    sub_has_black = True
                                elif f.endswith('.white'):
                                    sub_has_white = True
                                if sub_has_black and sub_has_white:
                                    break
                        except PermissionError:
                            # 跳过没有权限访问的目录
                            continue
                        
                        if sub_has_black or sub_has_white:
                            valid_dirs.append(os.path.join(d, sub_d))
    return valid_dirs

SAMPLE_DIRS = get_valid_sample_dirs()

@app.route('/')
def index():
    return render_template('index.html', sample_dirs=SAMPLE_DIRS)

@app.route('/start_test', methods=['POST'])
def start_test():
    global is_testing, current_process, test_logs
    
    if is_testing:
        return jsonify({'status': 'error', 'message': '测试正在进行中，请稍后再试'})
    
    # 获取表单数据
    sample_dir = request.form.get('sample_dir', '1').strip()
    target_url = request.form.get('target_url', '').strip()
    threads = request.form.get('threads', '10').strip()
    timeout = request.form.get('timeout', '10,30').strip()
    max_retries = request.form.get('max_retries', '3').strip()
    custom_code = request.form.get('custom_code', '403').strip()
    rst_detect = request.form.get('rst_detect', 'off').strip()
    keyword = request.form.get('keyword', '').strip()
    debug = request.form.get('debug', 'off').strip()
    output_csv = request.form.get('output_csv', 'off').strip()
    csv_path = request.form.get('csv_path', '').strip()
    output_samples = request.form.get('output_samples', 'off').strip()
    samples_path = request.form.get('samples_path', '').strip()
    
    # 构建命令
    cmd = [sys.executable, 'waf_tester.py', '-d', sample_dir]
    
    if target_url:
        cmd.extend(['-t', target_url])
    
    cmd.extend(['--threads', threads])
    cmd.extend(['--timeout', timeout])
    cmd.extend(['--max-retries', max_retries])
    cmd.extend(['-C', custom_code])
    
    if rst_detect == 'on':
        cmd.append('-R')
    
    if keyword:
        cmd.extend(['-K', keyword])
    
    if debug == 'on':
        cmd.append('--debug')
    
    # 处理输出CSV结果
    if output_csv == 'on' and csv_path:
        cmd.extend(['--output', csv_path])
    
    # 处理输出样本目录
    if output_samples == 'on' and samples_path:
        cmd.extend(['--split', samples_path])
    
    # 清空之前的日志
    test_logs = []
    
    def run_test():
        global is_testing, current_process
        is_testing = True
        
        try:
            # 打印后台调度的命令行参数
            cmd_str = ' '.join([f"'{arg}'" if ' ' in arg or '"' in arg else arg for arg in cmd])
            print(f"\n执行扫描任务：{cmd_str}\n")
            print(f"执行命令列表: {cmd}")  # 额外打印命令列表便于调试
            
            # 启动测试进程 - 使用shell=False更安全
            current_process = subprocess.Popen(
                cmd,  # cmd已经是列表格式，直接使用
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                shell=False
            )
            
            # 读取输出 - 使用更可靠的方式确保实时读取
            if current_process.stdout:
                while is_testing and current_process.poll() is None:
                    try:
                        line = current_process.stdout.readline()
                        if line:
                            line = line.strip()
                            if line:
                                test_logs.append(line)
                                result_queue.put({'type': 'log', 'data': line})
                        else:
                            # 防止无输出时的死循环
                            time.sleep(0.1)
                    except Exception as e:
                        error_message = f"读取输出时出错: {str(e)}"
                        result_queue.put({'type': 'error', 'data': error_message})
                        test_logs.append(error_message)
                        print(error_message)
                        break
                
                # 读取剩余输出
                try:
                    for line in current_process.stdout:
                        line = line.strip()
                        if line:
                            test_logs.append(line)
                            result_queue.put({'type': 'log', 'data': line})
                except Exception as e:
                    print(f"读取剩余输出时出错: {str(e)}")
            
            # 等待进程结束
            if current_process:
                current_process.wait()
                # 发送测试完成信号
                result_queue.put({'type': 'complete', 'data': f'测试完成，退出码：{current_process.returncode}'})
        except Exception as e:
            result_queue.put({'type': 'error', 'data': f'测试出错：{str(e)}'})
        finally:
            is_testing = False
            current_process = None
    
    # 启动测试线程
    threading.Thread(target=run_test, daemon=True).start()
    
    return jsonify({'status': 'success', 'message': '测试已开始'})

@app.route('/get_results')
def get_results():
    """获取测试结果"""
    results = []
    while not result_queue.empty():
        results.append(result_queue.get())
    return jsonify({'results': results})

@app.route('/stop_test')
def stop_test():
    """停止测试"""
    global is_testing, current_process
    
    if is_testing and current_process:
        current_process.terminate()
        is_testing = False
        current_process = None
        return jsonify({'status': 'success', 'message': '测试已停止'})
    else:
        return jsonify({'status': 'error', 'message': '没有正在进行的测试'})



@app.route('/get_sample_dirs')
def get_sample_dirs():
    """获取可用的样本目录"""
    global SAMPLE_DIRS
    SAMPLE_DIRS = get_valid_sample_dirs()
    return jsonify({'sample_dirs': SAMPLE_DIRS})

@app.route('/download_file/<path:filename>')
def download_file(filename):
    """提供文件下载功能"""
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    # 创建 templates 目录
    os.makedirs('templates', exist_ok=True)
    
    # 创建 index.html 模板文件
    index_html = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>python_test_waf</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        h1 {
            text-align: center;
            margin-bottom: 30px;
            color: #2c3e50;
        }
        
        .form-section {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
        }
        
        .form-row {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 15px;
        }
        
        .form-group {
            flex: 1;
            min-width: 200px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #555;
        }
        
        input[type="text"], input[type="number"], select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }
        
        input[type="checkbox"] {
            margin-right: 5px;
        }
        
        .checkbox-group {
            display: flex;
            align-items: center;
        }
        
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            font-weight: bold;
            margin-right: 10px;
        }
        
        .btn-primary {
            background-color: #3498db;
            color: white;
        }
        
        .btn-primary:hover {
            background-color: #2980b9;
        }
        
        .btn-danger {
            background-color: #e74c3c;
            color: white;
        }
        
        .btn-danger:hover {
            background-color: #c0392b;
        }
        
        .results-section {
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }
        
        .logs {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            max-height: 500px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 14px;
            line-height: 1.5;
            border: 1px solid #ddd;
        }
        
        .log-line {
            margin-bottom: 5px;
        }
        
        .log-line:nth-child(odd) {
            background-color: #e9ecef;
        }
        
        .status {
            margin-bottom: 15px;
            font-weight: bold;
        }
        
        .status.running {
            color: #e67e22;
        }
        
        .status.idle {
            color: #27ae60;
        }
        
        .status.error {
            color: #e74c3c;
        }
        
        @media (max-width: 768px) {
            .form-row {
                flex-direction: column;
            }
            
            .form-group {
                min-width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>python_test_waf</h1>
        
        <div class="form-section">
            <h2>测试参数设置</h2>
            <form id="test-form">
                <div class="form-row">
                    <div class="form-group">
                        <label for="sample_dir">样本目录</label>
                        <select id="sample_dir" name="sample_dir">
                            {% for dir in sample_dirs %}
                                <option value="{{ dir }}">{{ dir }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="target_url">靶机地址</label>
                        <input type="text" id="target_url" name="target_url" placeholder="http://127.0.0.1" value="http://127.0.0.1">
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="threads">并发线程数</label>
                        <input type="number" id="threads" name="threads" value="10" min="1" max="100">
                    </div>
                    <div class="form-group">
                        <label for="timeout">超时设置 (连接超时,读取超时 秒)</label>
                        <input type="text" id="timeout" name="timeout" value="10,30" placeholder="10,30">
                    </div>
                    <div class="form-group">
                        <label for="max_retries">最大重传次数</label>
                        <input type="number" id="max_retries" name="max_retries" value="3" min="1" max="10">
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <label for="custom_code">自定义 WAF 拦截状态码</label>
                        <input type="number" id="custom_code" name="custom_code" value="403" min="100" max="599">
                    </div>
                    <div class="form-group">
                        <label for="keyword">响应关键字</label>
                        <input type="text" id="keyword" name="keyword" placeholder="Forbidden">
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group checkbox-group">
                        <input type="checkbox" id="rst_detect" name="rst_detect">
                        <label for="rst_detect">检测 RST 拦截</label>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" id="debug" name="debug">
                        <label for="debug">启用调试模式</label>
                    </div>
                </div>
                
                <div class="form-row">
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="output_csv" name="output_csv">
                            <label for="output_csv">输出 CSV 结果</label>
                        </div>
                        <input type="text" id="csv_path" name="csv_path" placeholder="results.csv" style="margin-top: 5px; display: none;">
                    </div>
                    <div class="form-group">
                        <div class="checkbox-group">
                            <input type="checkbox" id="output_samples" name="output_samples">
                            <label for="output_samples">输出样本目录</label>
                        </div>
                        <input type="text" id="samples_path" name="samples_path" placeholder="test_results" value="test_results" style="margin-top: 5px; display: none;">
                    </div>
                </div>
                
                <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                    <button type="button" class="btn btn-primary" id="start-btn">开始测试</button>
                    <button type="button" class="btn btn-danger" id="stop-btn">停止测试</button>
                    <span id="status" class="status idle">就绪</span>
                    <div id="results-links" style="margin-left: auto;"></div>
                </div>
            </form>
        </div>
        
        <div class="results-section">
            <h2>测试结果</h2>
            <div id="logs" class="logs"></div>
        </div>
    </div>
    
    <script>
        let isTesting = false;
        let logInterval = null;
        
        // 更新状态显示
        function updateStatus(status) {
            const statusEl = document.getElementById('status');
            statusEl.className = `status ${status}`;
            switch(status) {
                case 'running':
                    statusEl.textContent = '测试进行中...';
                    break;
                case 'idle':
                    statusEl.textContent = '就绪';
                    break;
                case 'error':
                    statusEl.textContent = '错误';
                    break;
            }
        }
        
        // 开始测试
        document.getElementById('start-btn').addEventListener('click', function() {
            if (isTesting) return;
            
            // 处理表单数据，确保复选框的值正确
            const form = document.getElementById('test-form');
            const data = {};
            
            // 处理所有输入字段
            const allInputs = form.querySelectorAll('input, select');
            allInputs.forEach(input => {
                if (input.type === 'checkbox') {
                    data[input.name] = input.checked ? 'on' : 'off';
                } else {
                    data[input.name] = input.value;
                }
            });
            
            // 检查必填项
            if (!data.target_url) {
                alert('请输入靶机地址');
                return;
            }
            
            // 清空日志和结果链接
            document.getElementById('logs').innerHTML = '';
            document.getElementById('results-links').innerHTML = '';
            
            // 开始测试
            fetch('/start_test', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams(data)
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (data.status === 'success') {
                    isTesting = true;
                    updateStatus('running');
                    // 开始轮询获取日志，调整为2秒一次以减少资源浪费
                    if (!logInterval) {
                        logInterval = setInterval(fetchResults, 2000); // 调整为2秒一次，减少服务器压力
                    }
                } else {
                    alert(data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('测试启动失败: ' + error.message);
            });
        });
        
        // 停止测试
        document.getElementById('stop-btn').addEventListener('click', function() {
            fetch('/stop_test')
            .then(response => response.json())
            .then(data => {
                alert(data.message);
                isTesting = false;
                updateStatus('idle');
                if (logInterval) {
                    clearInterval(logInterval);
                    logInterval = null;
                }
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
        
        // 带超时的fetch函数
        function fetchWithTimeout(url, options = {}, timeout = 10000) {
            return Promise.race([
                fetch(url, options),
                new Promise((_, reject) => 
                    setTimeout(() => reject(new Error('请求超时')), timeout)
                )
            ]);
        }

        // 获取测试结果
        function fetchResults() {
            fetchWithTimeout('/get_results', {}, 15000) // 添加15秒超时
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                const logsEl = document.getElementById('logs');
                data.results.forEach(result => {
                    const logLine = document.createElement('div');
                    logLine.className = 'log-line';
                    logLine.textContent = result.data;
                    logsEl.appendChild(logLine);
                    // 滚动到底部
                    logsEl.scrollTop = logsEl.scrollHeight;
                    
                    if (result.type === 'complete' || result.type === 'error') {
                        isTesting = false;
                        updateStatus('idle');
                        if (logInterval) {
                            clearInterval(logInterval);
                            logInterval = null;
                        }
                        
                        // 显示结果链接
                        displayResultsLinks();
                        
                        // 测试完成后自动关闭输出复选框
                        document.getElementById('output_csv').checked = false;
                        document.getElementById('output_samples').checked = false;
                        
                        // 隐藏对应的输入框
                        document.getElementById('csv_path').style.display = 'none';
                        document.getElementById('samples_path').style.display = 'none';
                        
                        // 测试完成后刷新样本目录列表
                        refreshSampleDirs();
                    }
                });
            })
            .catch(error => {
                console.error('Error:', error);
            });
        }
        
        // 显示结果链接
        function displayResultsLinks() {
            const resultsLinksEl = document.getElementById('results-links');
            resultsLinksEl.innerHTML = '';
            
            // 检查是否有CSV文件生成
            const csvPath = document.getElementById('csv_path').value;
            if (document.getElementById('output_csv').checked && csvPath) {
                const csvLink = document.createElement('a');
                csvLink.href = `/download_file/${encodeURIComponent(csvPath)}`;
                csvLink.textContent = `下载 CSV 结果 (${csvPath})`;
                csvLink.className = 'btn btn-primary';
                csvLink.style.marginRight = '10px';
                csvLink.style.marginBottom = '10px';
                resultsLinksEl.appendChild(csvLink);
            }
            
            // 检查是否有样本目录生成
            const samplesPath = document.getElementById('samples_path').value;
            if (document.getElementById('output_samples').checked && samplesPath) {
                const samplesLink = document.createElement('a');
                samplesLink.href = `javascript:void(0);`;
                samplesLink.textContent = `查看样本目录 (${samplesPath})`;
                samplesLink.className = 'btn btn-secondary';
                samplesLink.style.marginRight = '10px';
                samplesLink.style.marginBottom = '10px';
                samplesLink.onclick = function() {
                    alert(`样本目录已生成在: ${samplesPath}\n您可以在服务器上查看该目录`);
                };
                resultsLinksEl.appendChild(samplesLink);
            }
        }
        
        // 定期刷新样本目录列表
        function refreshSampleDirs() {
            fetch('/get_sample_dirs')
            .then(response => response.json())
            .then(data => {
                const selectEl = document.getElementById('sample_dir');
                const currentValue = selectEl.value;
                selectEl.innerHTML = '';
                data.sample_dirs.forEach(dir => {
                    const option = document.createElement('option');
                    option.value = dir;
                    option.textContent = dir;
                    if (dir === currentValue) {
                        option.selected = true;
                    }
                    selectEl.appendChild(option);
                });
            })
            .catch(error => {
                console.error('Error:', error);
            });
        }
        
        // 生成带时间戳的文件名
        function generateTimestamp() {
            const now = new Date();
            const year = now.getFullYear();
            const month = String(now.getMonth() + 1).padStart(2, '0');
            const day = String(now.getDate()).padStart(2, '0');
            const hour = String(now.getHours()).padStart(2, '0');
            const minute = String(now.getMinutes()).padStart(2, '0');
            const second = String(now.getSeconds()).padStart(2, '0');
            return `${year}${month}${day}_${hour}${minute}${second}`;
        }
        
        // 更新带时间戳的默认值
        function updateTimestampDefaults() {
            const timestamp = generateTimestamp();
            document.getElementById('csv_path').value = `results_${timestamp}.csv`;
            document.getElementById('samples_path').value = `test_results_${timestamp}`;
        }
        
        // 处理复选框显示/隐藏逻辑
        function setupCheckboxHandlers() {
            // 输出CSV结果复选框
            const outputCsvCheckbox = document.getElementById('output_csv');
            const csvPathInput = document.getElementById('csv_path');
            outputCsvCheckbox.addEventListener('change', function() {
                csvPathInput.style.display = this.checked ? 'block' : 'none';
                if (this.checked) {
                    // 每次勾选时，更新文件名
                    const timestamp = generateTimestamp();
                    csvPathInput.value = `results_${timestamp}.csv`;
                }
            });
            
            // 输出样本目录复选框
            const outputSamplesCheckbox = document.getElementById('output_samples');
            const samplesPathInput = document.getElementById('samples_path');
            outputSamplesCheckbox.addEventListener('change', function() {
                samplesPathInput.style.display = this.checked ? 'block' : 'none';
                if (this.checked) {
                    // 每次勾选时，更新文件名
                    const timestamp = generateTimestamp();
                    samplesPathInput.value = `test_results_${timestamp}`;
                }
            });
        }
        
        // 初始化
        window.onload = function() {
            refreshSampleDirs();
            setupCheckboxHandlers();
            // 初始生成带时间戳的默认值
            updateTimestampDefaults();
        };
    </script>
</body>
</html>
    '''
    
    # 写入模板文件
    os.makedirs('templates', exist_ok=True)
    with open('templates/index.html', 'w', encoding='utf-8') as f:
        f.write(index_html)
    
    print("WebUI 已创建完成！")
    print("使用以下命令启动 WebUI：")
    print(f"python3 {os.path.basename(__file__)}")
    print("然后在浏览器中访问：http://localhost:5001")
    
    # 启动 Flask 应用 - 配置为处理并发请求
    app.run(debug=True, host='0.0.0.0', port=5001, threaded=True)
