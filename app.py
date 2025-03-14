from flask import Flask, Response, render_template, request, jsonify, redirect, url_for
import socket
import subprocess
import platform
import psutil
import os
import json
import time
import datetime
import uuid
import base64
import hashlib
import re
import ipaddress
import urllib.parse
import requests
import whois
import dns.resolver
import netifaces
import random
import string
from bs4 import BeautifulSoup
from cryptography.fernet import Fernet
from log_analyzer import LogAnalyzer
from conversion_utils import ConversionTools
from api.monitoring import monitoring_bp
from development_api import dev_bp
# Initialize the LogAnalyzer
log_analyzer = LogAnalyzer()


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
app.register_blueprint(monitoring_bp)
app.register_blueprint(dev_bp)


# ============= Home and Navigation =============
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/network')
def network_tools():
    return render_template('network_tools.html')

# New tool categories
@app.route('/database')
def database_tools():
    return render_template('database_tools.html')
@app.route('/logs')
def log_tools():
    return render_template('log_tools.html')

@app.route('/api/parse_log', methods=['POST'])
def parse_log():
    data = request.get_json()

    log_content = data.get('log_content', '')
    format_type = data.get('format', 'auto')
    custom_format = data.get('custom_format')
    extract_timestamp = data.get('extract_timestamp', True)
    categorize_entries = data.get('categorize_entries', True)
    identify_patterns = data.get('identify_patterns', True)
    filter_expr = data.get('filter')

    result = log_analyzer.parse_log(
        log_content, 
        format_type, 
        custom_format, 
        extract_timestamp, 
        categorize_entries, 
        identify_patterns, 
        filter_expr
    )

    return jsonify(result)

@app.route('/api/find_patterns', methods=['POST'])
def find_patterns():
    data = request.get_json()

    log_content = data.get('log_content', '')
    pattern_type = data.get('pattern_type', 'errors')
    custom_pattern = data.get('custom_pattern')
    case_sensitive = data.get('case_sensitive', False)

    result = log_analyzer.find_patterns(
        log_content, 
        pattern_type, 
        custom_pattern, 
        case_sensitive
    )

    return jsonify(result)
@app.route('/api/visualize_log', methods=['POST'])
def visualize_log():
    data = request.get_json()

    log_content = data.get('log_content', '')
    visualization_type = data.get('visualization_type', 'timeseries')
    time_frame = data.get('time_frame', 'all')

    result = log_analyzer.visualize_log(
        log_content, 
        visualization_type, 
        time_frame
    )

    return jsonify(result)
@app.route('/api/monitor_log', methods=['POST'])
def monitor_log():
    data = request.get_json()

    log_file_path = data.get('log_file_path', '')
    format_type = data.get('format', 'auto')
    alert_keywords = data.get('alert_keywords', [])

    result = log_analyzer.monitor_log(
        log_file_path, 
        format_type, 
        alert_keywords
    )

    return jsonify(result)
@app.route('/convert')
def conversion_tools():
    return render_template('conversion_tools.html')
@app.route('/api/convert_format', methods=['POST'])
def api_convert_format():
    data = request.json
    source_format = data.get('source_format')
    target_format = data.get('target_format')
    content = data.get('content')
    pretty_print = data.get('pretty_print', True)
    preserve_order = data.get('preserve_order', False)
    
    if not all([source_format, target_format, content]):
        return jsonify({'error': 'Missing required parameters'})
    
    try:
        result = ConversionTools.convert_format(
            content, source_format, target_format, pretty_print, preserve_order
        )
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/detect_format', methods=['POST'])
def api_detect_format():
    data = request.json
    content = data.get('content')
    
    if not content:
        return jsonify({'error': 'No content provided'})
    
    try:
        detected_format = ConversionTools.detect_format(content)
        return jsonify({'detected_format': detected_format})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/csv_to_json', methods=['POST'])
def api_csv_to_json():
    data = request.json
    csv_content = data.get('csv_content')
    delimiter = data.get('delimiter', ',')
    has_header = data.get('has_header', True)
    trim_whitespace = data.get('trim_whitespace', True)
    type_detection = data.get('type_detection', True)
    
    if not csv_content:
        return jsonify({'error': 'No CSV content provided'})
    
    try:
        result = ConversionTools.csv_to_json(
            csv_content, delimiter, has_header, trim_whitespace, type_detection
        )
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/transpose_csv', methods=['POST'])
def api_transpose_csv():
    data = request.json
    csv_content = data.get('csv_content')
    delimiter = data.get('delimiter', ',')
    
    if not csv_content:
        return jsonify({'error': 'No CSV content provided'})
    
    try:
        result = ConversionTools.transpose_csv(csv_content, delimiter)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/manipulate_csv', methods=['POST'])
def api_manipulate_csv():
    data = request.json
    csv_content = data.get('csv_content')
    manipulation_type = data.get('manipulation_type')
    
    if not csv_content or not manipulation_type:
        return jsonify({'error': 'Missing required parameters'})
    
    try:
        # Extract all other parameters to pass as kwargs
        kwargs = {k: v for k, v in data.items() 
                 if k not in ['csv_content', 'manipulation_type']}
        
        result = ConversionTools.manipulate_csv(csv_content, manipulation_type, **kwargs)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/format_code', methods=['POST'])
def api_format_code():
    data = request.json
    code = data.get('code')
    language = data.get('language')
    minify = data.get('minify', False)
    
    if not code or not language:
        return jsonify({'error': 'Missing required parameters'})
    
    try:
        # Extract formatting options
        indent_with_tabs = data.get('indent_with_tabs', False)
        indent_size = data.get('indent_size', 4)
        wrap_lines = data.get('wrap_lines', True)
        
        result = ConversionTools.format_code(
            code, language, indent_with_tabs, indent_size, wrap_lines, minify
        )
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/encode_url', methods=['POST'])
def api_encode_url():
    data = request.json
    text = data.get('text')
    
    if not text:
        return jsonify({'error': 'No text provided'})
    
    try:
        result = ConversionTools.encode_url(text)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/decode_url', methods=['POST'])
def api_decode_url():
    data = request.json
    text = data.get('text')
    
    if not text:
        return jsonify({'error': 'No text provided'})
    
    try:
        result = ConversionTools.decode_url(text)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/encode_base64', methods=['POST'])
def api_encode_base64():
    data = request.json
    text = data.get('text')
    
    if not text:
        return jsonify({'error': 'No text provided'})
    
    try:
        result = ConversionTools.encode_base64(text)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/decode_base64', methods=['POST'])
def api_decode_base64():
    data = request.json
    text = data.get('text')
    
    if not text:
        return jsonify({'error': 'No text provided'})
    
    try:
        result = ConversionTools.decode_base64(text)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/encode_file_base64', methods=['POST'])
def api_encode_file_base64():
    data = request.json
    file_data = data.get('data')
    
    if not file_data:
        return jsonify({'error': 'No file data provided'})
    
    try:
        result = ConversionTools.encode_file_base64(file_data)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/decode_file_base64', methods=['POST'])
def api_decode_file_base64():
    data = request.json
    base64_data = data.get('data')
    
    if not base64_data:
        return jsonify({'error': 'No Base64 data provided'})
    
    try:
        file_data = ConversionTools.decode_file_base64(base64_data)
        return Response(file_data, mimetype='application/octet-stream')
    except Exception as e:
        return jsonify({'error': str(e)})
@app.route('/api/encode_html', methods=['POST'])
def api_encode_html():
    data = request.json
    text = data.get('text')
    
    if not text:
        return jsonify({'error': 'No text provided'})
    
    try:
        result = ConversionTools.encode_html(text)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/decode_html', methods=['POST'])
def api_decode_html():
    data = request.json
    text = data.get('text')
    
    if not text:
        return jsonify({'error': 'No text provided'})
    
    try:
        result = ConversionTools.decode_html(text)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/monitor')
def monitoring_tools():
    return render_template('monitoring_tools.html')

@app.route('/monitor2')
def monitoring_tools2():
    return render_template('monitoring_tools2.html')


@app.route('/dev')
def development_tools():
    return render_template('development_tools.html')

@app.route('/infrastructure')
def infrastructure_tools():
    return render_template('infrastructure_tools.html')

@app.route('/backup')
def backup_tools():
    return render_template('backup_tools.html')

@app.route('/collab')
def collaboration_tools():
    return render_template('collaboration_tools.html')@app.route('/api/ping', methods=['POST'])
def ping():
    data = request.get_json()
    hostname = data.get('hostname', '')
    
    if not hostname:
        return jsonify({'error': 'Hostname is required'}), 400
    
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(f"ping -n 4 {hostname}", shell=True).decode()
        else:
            output = subprocess.check_output(f"ping -c 4 {hostname}", shell=True).decode()
        return jsonify({'output': output})
    except subprocess.CalledProcessError:
        return jsonify({'error': 'Ping failed. Host may be unreachable.'}), 500

@app.route('/api/traceroute', methods=['POST'])
def traceroute():
    data = request.get_json()
    hostname = data.get('hostname', '')
    
    if not hostname:
        return jsonify({'error': 'Hostname is required'}), 400
    
    try:
        if platform.system().lower() == "windows":
            output = subprocess.check_output(f"tracert {hostname}", shell=True).decode()
        else:
            output = subprocess.check_output(f"traceroute {hostname}", shell=True).decode()
        return jsonify({'output': output})
    except subprocess.CalledProcessError:
        return jsonify({'error': 'Traceroute failed'}), 500

@app.route('/api/dns_lookup', methods=['POST'])
def dns_lookup():
    data = request.get_json()
    domain = data.get('domain', '')
    record_type = data.get('record_type', 'A')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        results = []
        answers = dns.resolver.resolve(domain, record_type)
        for answer in answers:
            results.append(str(answer))
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/port_scan', methods=['POST'])
def port_scan():
    data = request.get_json()
    host = data.get('host', '')
    port_range = data.get('port_range', '1-1000')
    
    if not host:
        return jsonify({'error': 'Host is required'}), 400
    
    try:
        start_port, end_port = map(int, port_range.split('-'))
        if end_port - start_port > 1000:  # Limit for safety
            return jsonify({'error': 'Port range too large (max 1000 ports)'}), 400
            
        results = []
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                results.append({'port': port, 'status': 'open', 'service': service})
            sock.close()
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/whois', methods=['POST'])
def whois_lookup():
    data = request.get_json()
    domain = data.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        w = whois.whois(domain)
        return jsonify({'result': str(w)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/local_network', methods=['GET'])
def local_network():
    interfaces = []
    for interface in netifaces.interfaces():
        interface_data = {'name': interface, 'addresses': []}
        addresses = netifaces.ifaddresses(interface)
        
        # Get IPv4 addresses
        if netifaces.AF_INET in addresses:
            for item in addresses[netifaces.AF_INET]:
                interface_data['addresses'].append({
                    'type': 'IPv4',
                    'addr': item.get('addr', ''),
                    'netmask': item.get('netmask', '')
                })
                
        # Get IPv6 addresses
        if netifaces.AF_INET6 in addresses:
            for item in addresses[netifaces.AF_INET6]:
                interface_data['addresses'].append({
                    'type': 'IPv6',
                    'addr': item.get('addr', ''),
                    'netmask': item.get('netmask', '')
                })
                
        # Get MAC address
        if netifaces.AF_LINK in addresses:
            for item in addresses[netifaces.AF_LINK]:
                interface_data['addresses'].append({
                    'type': 'MAC',
                    'addr': item.get('addr', '')
                })
                
        interfaces.append(interface_data)
    
    return jsonify({'interfaces': interfaces})

# ============= System Tools =============
@app.route('/system')
def system_tools():
    return render_template('system_tools.html')

@app.route('/api/system_info', methods=['GET'])
def system_info():
    info = {
        'system': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'cpu_count': psutil.cpu_count(logical=False),
        'logical_cpu_count': psutil.cpu_count(logical=True),
        'memory': {
            'total': psutil.virtual_memory().total,
            'available': psutil.virtual_memory().available,
            'percent': psutil.virtual_memory().percent,
        },
        'disk': {
            'total': psutil.disk_usage('/').total,
            'used': psutil.disk_usage('/').used,
            'free': psutil.disk_usage('/').free,
            'percent': psutil.disk_usage('/').percent,
        },
        'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
    }
    return jsonify(info)

@app.route('/api/processes', methods=['GET'])
def processes():
    process_list = []
    for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
        process_list.append(proc.info)
    
    return jsonify({'processes': process_list})

@app.route('/api/network_connections', methods=['GET'])
def network_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        connection = {
            'fd': conn.fd,
            'family': conn.family,
            'type': conn.type,
            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
            'status': conn.status,
            'pid': conn.pid
        }
        connections.append(connection)
    
    return jsonify({'connections': connections})

# ============= Security Tools =============
@app.route('/security')
def security_tools():
    return render_template('security_tools.html')

@app.route('/api/password_generator', methods=['POST'])
def password_generator():
    data = request.get_json()
    length = int(data.get('length', 12))
    include_uppercase = data.get('include_uppercase', True)
    include_lowercase = data.get('include_lowercase', True)
    include_numbers = data.get('include_numbers', True)
    include_special = data.get('include_special', True)
    
    if length < 4 or length > 100:
        return jsonify({'error': 'Length must be between 4 and 100'}), 400
    
    chars = ''
    if include_uppercase:
        chars += string.ascii_uppercase
    if include_lowercase:
        chars += string.ascii_lowercase
    if include_numbers:
        chars += string.digits
    if include_special:
        chars += string.punctuation
    
    if not chars:
        return jsonify({'error': 'At least one character type must be selected'}), 400
    
    password = ''.join(random.choice(chars) for _ in range(length))
    
    # Calculate password strength
    strength = 0
    if len(password) >= 8:
        strength += 1
    if len(password) >= 12:
        strength += 1
    if include_uppercase and any(c.isupper() for c in password):
        strength += 1
    if include_lowercase and any(c.islower() for c in password):
        strength += 1
    if include_numbers and any(c.isdigit() for c in password):
        strength += 1
    if include_special and any(c in string.punctuation for c in password):
        strength += 1
    
    strength_text = ['Very Weak', 'Weak', 'Moderate', 'Strong', 'Very Strong', 'Excellent'][min(strength, 5)]
    
    return jsonify({'password': password, 'strength': strength_text})

@app.route('/api/hash_generator', methods=['POST'])
def hash_generator():
    data = request.get_json()
    text = data.get('text', '')
    algorithm = data.get('algorithm', 'md5')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        result = {}
        algorithms = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
        
        if algorithm == 'all':
            for algo in algorithms:
                h = hashlib.new(algo)
                h.update(text.encode())
                result[algo] = h.hexdigest()
        else:
            h = hashlib.new(algorithm)
            h.update(text.encode())
            result[algorithm] = h.hexdigest()
            
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/encrypt_decrypt', methods=['POST'])
def encrypt_decrypt():
    data = request.get_json()
    text = data.get('text', '')
    action = data.get('action', 'encrypt')
    key = data.get('key', '')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        if action == 'encrypt':
            if not key:
                key = Fernet.generate_key().decode()
                
            f = Fernet(key.encode() if isinstance(key, str) else key)
            encrypted = f.encrypt(text.encode()).decode()
            return jsonify({'result': encrypted, 'key': key})
        else:
            if not key:
                return jsonify({'error': 'Key is required for decryption'}), 400
                
            f = Fernet(key.encode() if isinstance(key, str) else key)
            decrypted = f.decrypt(text.encode()).decode()
            return jsonify({'result': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============= Text Tools =============
@app.route('/text')
def text_tools():
    return render_template('text_tools.html')

@app.route('/api/regex_tester', methods=['POST'])
def regex_tester():
    data = request.get_json()
    pattern = data.get('pattern', '')
    text = data.get('text', '')
    
    if not pattern or not text:
        return jsonify({'error': 'Pattern and text are required'}), 400
    
    try:
        regex = re.compile(pattern)
        matches = []
        for match in regex.finditer(text):
            matches.append({
                'start': match.start(),
                'end': match.end(),
                'group': match.group(0),
                'groups': match.groups()
            })
        return jsonify({'matches': matches, 'count': len(matches)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/base64', methods=['POST'])
def base64_tool():
    data = request.get_json()
    text = data.get('text', '')
    action = data.get('action', 'encode')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        if action == 'encode':
            result = base64.b64encode(text.encode()).decode()
        else:
            result = base64.b64decode(text.encode()).decode()
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
# Continue from previous code...

@app.route('/api/url_encode_decode', methods=['POST'])
def url_encode_decode():
    data = request.get_json()
    text = data.get('text', '')
    action = data.get('action', 'encode')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        if action == 'encode':
            result = urllib.parse.quote(text)
        else:
            result = urllib.parse.unquote(text)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/json_formatter', methods=['POST'])
def json_formatter():
    data = request.get_json()
    text = data.get('text', '')
    
    if not text:
        return jsonify({'error': 'JSON text is required'}), 400
    
    try:
        parsed = json.loads(text)
        formatted = json.dumps(parsed, indent=4)
        return jsonify({'result': formatted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/text_case_converter', methods=['POST'])
def text_case_converter():
    data = request.get_json()
    text = data.get('text', '')
    case_type = data.get('case_type', 'lower')
    
    if not text:
        return jsonify({'error': 'Text is required'}), 400
    
    try:
        if case_type == 'lower':
            result = text.lower()
        elif case_type == 'upper':
            result = text.upper()
        elif case_type == 'title':
            result = text.title()
        elif case_type == 'capitalize':
            result = text.capitalize()
        elif case_type == 'snake':
            result = '_'.join(word.lower() for word in re.findall(r'\w+', text))
        elif case_type == 'camel':
            words = re.findall(r'\w+', text)
            result = words[0].lower() + ''.join(word.capitalize() for word in words[1:])
        else:
            result = text
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============= Web Tools =============
@app.route('/web')
def web_tools():
    return render_template('web_tools.html')

@app.route('/api/http_request', methods=['POST'])
def http_request():
    data = request.get_json()
    url = data.get('url', '')
    method = data.get('method', 'GET')
    headers = data.get('headers', {})
    body = data.get('body', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=10)
        elif method == 'POST':
            response = requests.post(url, headers=headers, data=body, timeout=10)
        elif method == 'PUT':
            response = requests.put(url, headers=headers, data=body, timeout=10)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers, timeout=10)
        else:
            return jsonify({'error': 'Unsupported method'}), 400
            
        result = {
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'content': response.text[:10000],  # Limiting content size
            'response_time': response.elapsed.total_seconds(),
        }
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/website_info', methods=['POST'])
def website_info():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        title = soup.title.string if soup.title else "No Title"
        meta_description = soup.find("meta", {"name": "description"})
        description = meta_description["content"] if meta_description else "No Description"
        
        meta_keywords = soup.find("meta", {"name": "keywords"})
        keywords = meta_keywords["content"] if meta_keywords else "No Keywords"
        
        # Extract links
        links = []
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('http'):
                links.append(href)
            elif href.startswith('/'):
                # Convert relative URL to absolute
                base_url = urllib.parse.urlparse(url)
                abs_url = f"{base_url.scheme}://{base_url.netloc}{href}"
                links.append(abs_url)
        
        # Limit links to 100
        links = links[:100]
        
        # Extract images
        images = []
        for img in soup.find_all('img', src=True):
            src = img['src']
            if src.startswith('http'):
                images.append(src)
            elif src.startswith('/'):
                base_url = urllib.parse.urlparse(url)
                abs_url = f"{base_url.scheme}://{base_url.netloc}{src}"
                images.append(abs_url)
        
        # Limit images to 20
        images = images[:20]
        
        result = {
            'title': title,
            'description': description,
            'keywords': keywords,
            'headers': dict(response.headers),
            'status_code': response.status_code,
            'content_type': response.headers.get('content-type'),
            'links_count': len(links),
            'links': links,
            'images_count': len(images),
            'images': images,
        }
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ip_info', methods=['POST'])
def ip_info():
    data = request.get_json()
    ip = data.get('ip', '')
    
    if not ip:
        return jsonify({'error': 'IP address is required'}), 400
    
    try:
        # Validate IP
        ipaddress.ip_address(ip)
        
        # Use ipinfo.io API for IP information
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Failed to retrieve IP information'}), 500
    except ValueError:
        return jsonify({'error': 'Invalid IP address'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# ============= File Tools =============
@app.route('/file')
def file_tools():
    return render_template('file_tools.html')

@app.route('/api/file_hash', methods=['POST'])
def file_hash():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    try:
        # Calculate various hashes
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        sha256_hash = hashlib.sha256()
        
        chunk_size = 4096
        while True:
            data = file.read(chunk_size)
            if not data:
                break
            md5_hash.update(data)
            sha1_hash.update(data)
            sha256_hash.update(data)
            
        result = {
            'filename': file.filename,
            'filesize': file.tell(),
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
            'sha256': sha256_hash.hexdigest(),
        }
        
        # Reset file pointer
        file.seek(0)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============= Main Application =============
if __name__ == '__main__':
    app.run(debug=True)
# Note: In a production environment, set debug=False and configure a proper WSGI server.
# Note: This is a simplified version and may need further enhancements for production use.
