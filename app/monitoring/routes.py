from flask import render_template, jsonify
from monitoring import monitoring
import psutil
import platform
import datetime
import os

# Main monitoring page
@monitoring.route('/monitoring')
def monitoring_tools():
    return render_template('monitoring_tools.html')

# API endpoints
@monitoring.route('/api/info', methods=['GET'])
def system_info():
    boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
    now = datetime.datetime.now()
    uptime = now - boot_time
    
    return jsonify({
        'system': platform.system(),
        'node': platform.node(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'boot_time': boot_time.strftime("%Y-%m-%d %H:%M:%S"),
        'uptime_seconds': uptime.total_seconds(),
        'uptime_formatted': f"{uptime.days} days, {uptime.seconds // 3600} hours, {(uptime.seconds // 60) % 60} minutes"
    })

@monitoring.route('/api/cpu', methods=['GET'])
def cpu_info():
    cpu_freq = psutil.cpu_freq()
    
    return jsonify({
        'physical_cores': psutil.cpu_count(logical=False),
        'total_cores': psutil.cpu_count(logical=True),
        'usage_percent': psutil.cpu_percent(),
        'min_frequency': cpu_freq.min if cpu_freq else 0,
        'max_frequency': cpu_freq.max if cpu_freq else 0,
        'current_frequency': cpu_freq.current if cpu_freq else 0,
        'load_avg': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else [0, 0, 0]
    })

@monitoring.route('/api/memory', methods=['GET'])
def memory_info():
    virtual_memory = psutil.virtual_memory()
    swap_memory = psutil.swap_memory()
    
    return jsonify({
        'virtual': {
            'total': virtual_memory.total,
            'available': virtual_memory.available,
            'used': virtual_memory.used,
            'percent': virtual_memory.percent,
            'formatted': {
                'total': format_bytes(virtual_memory.total),
                'available': format_bytes(virtual_memory.available),
                'used': format_bytes(virtual_memory.used)
            }
        },
        'swap': {
            'total': swap_memory.total,
            'used': swap_memory.used,
            'free': swap_memory.free,
            'percent': swap_memory.percent,
            'formatted': {
                'total': format_bytes(swap_memory.total),
                'used': format_bytes(swap_memory.used),
                'free': format_bytes(swap_memory.free)
            }
        }
    })

# Helper function to format bytes to human-readable format
def format_bytes(bytes_value):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.2f} PB"
