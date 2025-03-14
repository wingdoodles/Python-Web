from functools import wraps
import json
from flask import Blueprint, app, current_app, jsonify
from flask import request, has_request_context, session
import psutil
import datetime
import platform
import os
import sqlite3
import sys
import time
import threading
import uuid
from collections import deque, defaultdict
import re
import glob
from datetime import datetime, timedelta
from pathlib import Path
import socket

monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/api/monitoring')

# Global variables to track request metrics
request_history = deque(maxlen=100)  # Store last 100 requests
request_stats = {
    'count': 0,
    'routes': defaultdict(int),
    'status_codes': defaultdict(int),
    'methods': defaultdict(int),
    'ips': defaultdict(int),
    'start_time': time.time(),
    'response_times': []
}
# Request tracking decorator - you can add this to your app later
def track_request():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            start_time = time.time()
            response = f(*args, **kwargs)
            duration = time.time() - start_time
            
            # Skip monitoring endpoints to avoid recursive tracking
            if request.path.startswith('/api/monitoring'):
                return response
            
            # Update request stats
            request_stats['count'] += 1
            request_stats['routes'][request.path] += 1
            request_stats['methods'][request.method] += 1
            request_stats['status_codes'][response.status_code] += 1
            request_stats['ips'][request.remote_addr] += 1
            
            # Store response time (max 1000 times to avoid memory issues)
            if len(request_stats['response_times']) < 1000:
                request_stats['response_times'].append(duration)
            
            # Add to request history
            request_info = {
                'id': str(uuid.uuid4()),
                'timestamp': time.time(),
                'path': request.path,
                'method': request.method,
                'status_code': response.status_code,
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent', 'Unknown'),
                'duration': duration,
                'user_id': session.get('user_id', None) if has_request_context() and 'user_id' in session else None
            }
            request_history.append(request_info)
            
            return response
        return decorated_function
    return decorator


# System Information APIs
@monitoring_bp.route('/system/info', methods=['GET'])
def system_info():
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    now = datetime.now()
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

@monitoring_bp.route('/system/cpu', methods=['GET'])
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

@monitoring_bp.route('/system/memory', methods=['GET'])
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
@monitoring_bp.route('/system/disk', methods=['GET'])  # Added disk endpoint
def disk_info():
    try:
        partitions = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                partitions.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'opts': partition.opts,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent,
                    'formatted': {
                        'total': format_bytes(usage.total),
                        'used': format_bytes(usage.used),
                        'free': format_bytes(usage.free)
                    }
                })
            except (PermissionError, OSError):
                # Skip partitions that can't be accessed
                continue

        # Get disk I/O statistics if available
        io_stats = None
        try:
            disk_io = psutil.disk_io_counters()
            io_stats = {
                'read_count': disk_io.read_count,
                'write_count': disk_io.write_count,
                'read_bytes': disk_io.read_bytes,
                'write_bytes': disk_io.write_bytes,
                'formatted': {
                    'read_bytes': format_bytes(disk_io.read_bytes),
                    'write_bytes': format_bytes(disk_io.write_bytes)
                }
            }
        except:
            # Disk I/O might not be available on all systems
            pass

        return jsonify({
            'partitions': partitions,
            'io_stats': io_stats
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/system/processes', methods=['GET'])
def process_info():
    try:
        processes_list = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent', 'memory_info', 'create_time', 'num_threads']):
            try:
                pinfo = proc.info
                create_time = datetime.fromtimestamp(pinfo['create_time']).strftime("%Y-%m-%d %H:%M:%S")
                memory_info = pinfo.get('memory_info', None)
                
                # Add process to the list
                processes_list.append({
                    'pid': pinfo['pid'],
                    'name': pinfo['name'],
                    'username': pinfo.get('username', 'N/A'),
                    'status': pinfo['status'],
                    'cpu_percent': pinfo['cpu_percent'],
                    'memory_percent': pinfo['memory_percent'],
                    'memory_info': memory_info.rss if memory_info else 0,
                    'create_time': create_time,
                    'num_threads': pinfo['num_threads'],
                    'formatted': {
                        'memory_info': format_bytes(memory_info.rss if memory_info else 0)
                    }
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Sort processes by memory usage (descending)
        processes_list.sort(key=lambda x: x['memory_percent'], reverse=True)
        
        # Get the top 50 processes
        processes_list = processes_list[:50]
        
        # Get process counts by status
        status_counts = {status: 0 for status in ['running', 'sleeping', 'stopped', 'zombie']}
        for p in psutil.process_iter(['status']):
            try:
                status = p.info['status'].lower()
                if status in status_counts:
                    status_counts[status] += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        return jsonify({
            'processes': processes_list,
            'total_processes': len(list(psutil.process_iter())),
            'running_processes': status_counts['running'],
            'sleeping_processes': status_counts['sleeping'],
            'stopped_processes': status_counts.get('stopped', 0),
            'zombie_processes': status_counts.get('zombie', 0)
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/database/info', methods=['GET'])
def database_info():
    try:
        # Try to get database information from Flask-SQLAlchemy if available
        if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
            db = current_app.extensions['sqlalchemy'].db
            engine = db.engine
            
            # Get database type and version
            db_info = {
                'type': engine.name,
                'driver': engine.driver,
                'url': str(engine.url).replace(str(engine.url.password or ''), '****'),  # Hide password
            }
            
            # Get database version
            if engine.name == 'sqlite':
                conn = engine.raw_connection()
                version = conn.execute('SELECT sqlite_version()').fetchone()[0]
                db_info['version'] = version
                conn.close()
            elif engine.name == 'postgresql':
                version = engine.execute('SELECT version()').scalar()
                db_info['version'] = version
            elif engine.name == 'mysql':
                version = engine.execute('SELECT VERSION()').scalar()
                db_info['version'] = version
            
            return jsonify(db_info)
        
        # Fallback to basic information if SQLAlchemy is not available
        # Try to detect SQLite database
        app_dir = os.path.dirname(os.path.abspath(current_app.root_path))
        db_path = None
        
        # Check common database paths
        common_paths = [
            os.path.join(app_dir, 'instance', 'app.db'),
            os.path.join(app_dir, 'app.db'),
            os.path.join(app_dir, 'site.db'),
            os.path.join(app_dir, 'database.db')
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                db_path = path
                break
        
        if db_path:
            conn = sqlite3.connect(db_path)
            version = conn.execute('SELECT sqlite_version()').fetchone()[0]
            conn.close()
            
            return jsonify({
                'type': 'sqlite',
                'path': db_path,
                'version': version,
                'size': format_bytes(os.path.getsize(db_path))
            })
        
        return jsonify({
            'error': 'Could not detect database information. Please customize this endpoint for your specific database.'
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/database/stats', methods=['GET'])
def database_stats():
    try:
        # Try to get database stats from Flask-SQLAlchemy if available
        if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
            db = current_app.extensions['sqlalchemy'].db
            engine = db.engine
            
            stats = {
                'tables': 0,
                'size': 'Unknown',
                'connections': 'Unknown',
                'uptime': 'Unknown'
            }
            
            # Get table count
            if engine.name == 'sqlite':
                conn = engine.raw_connection()
                tables = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
                stats['tables'] = tables
                
                # Get database size
                db_path = engine.url.database
                if db_path and os.path.exists(db_path):
                    stats['size'] = format_bytes(os.path.getsize(db_path))
                
                conn.close()
            elif engine.name == 'postgresql':
                tables = engine.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'").scalar()
                stats['tables'] = tables
                
                # Get database size
                db_size = engine.execute("SELECT pg_size_pretty(pg_database_size(current_database()))").scalar()
                stats['size'] = db_size
                
                # Get connection count
                connections = engine.execute("SELECT COUNT(*) FROM pg_stat_activity").scalar()
                stats['connections'] = connections
                
                # Get uptime
                uptime = engine.execute("SELECT date_trunc('second', current_timestamp - pg_postmaster_start_time())").scalar()
                stats['uptime'] = str(uptime)
            elif engine.name == 'mysql':
                tables = engine.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()").scalar()
                stats['tables'] = tables
                
                # Get database size
                db_size = engine.execute("SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) FROM information_schema.tables WHERE table_schema = DATABASE()").scalar()
                stats['size'] = f"{db_size} MB"
                
                # Get connection count
                connections = engine.execute("SELECT COUNT(*) FROM information_schema.processlist").scalar()
                stats['connections'] = connections
                
                # Get uptime
                uptime = engine.execute("SELECT TIME_FORMAT(SEC_TO_TIME(VARIABLE_VALUE), '%Hh %im %ss') FROM performance_schema.global_status WHERE VARIABLE_NAME = 'Uptime'").scalar()
                stats['uptime'] = uptime
            
            return jsonify(stats)
        
        # Fallback to basic information if SQLAlchemy is not available
        # Try to detect SQLite database
        app_dir = os.path.dirname(os.path.abspath(current_app.root_path))
        db_path = None
        
        # Check common database paths
        common_paths = [
            os.path.join(app_dir, 'instance', 'app.db'),
            os.path.join(app_dir, 'app.db'),
            os.path.join(app_dir, 'site.db'),
            os.path.join(app_dir, 'database.db')
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                db_path = path
                break
        
        if db_path:
            conn = sqlite3.connect(db_path)
            tables = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
            conn.close()
            
            return jsonify({
                'tables': tables,
                'size': format_bytes(os.path.getsize(db_path)),
                'connections': 'N/A for SQLite',
                'uptime': 'N/A for SQLite'
            })
        
        return jsonify({
            'error': 'Could not detect database statistics. Please customize this endpoint for your specific database.'
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/database/tables', methods=['GET'])
def database_tables():
    try:
        # Try to get database tables from Flask-SQLAlchemy if available
        if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
            db = current_app.extensions['sqlalchemy'].db
            engine = db.engine
            
            tables = []
            
            if engine.name == 'sqlite':
                conn = engine.raw_connection()
                
                # Get table list
                table_list = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
                
                for table_name in [row[0] for row in table_list]:
                    # Skip SQLite system tables
                    if table_name.startswith('sqlite_'):
                        continue
                    
                    # Get row count
                    row_count = conn.execute(f"SELECT COUNT(*) FROM '{table_name}'").fetchone()[0]
                    
                    # Get column info
                    columns = conn.execute(f"PRAGMA table_info('{table_name}')").fetchall()
                    column_count = len(columns)
                    
                    # Get index info
                    indices = conn.execute(f"PRAGMA index_list('{table_name}')").fetchall()
                    index_count = len(indices)
                    
                    tables.append({
                        'name': table_name,
                        'row_count': row_count,
                        'column_count': column_count,
                        'index_count': index_count
                    })
                
                conn.close()
            elif engine.name == 'postgresql':
                # Get tables with row counts and sizes
                result = engine.execute("""
                    SELECT 
                        relname as table_name,
                        n_live_tup as row_count,
                        pg_size_pretty(pg_total_relation_size(relid)) as total_size
                    FROM pg_stat_user_tables
                    ORDER BY relname
                """).fetchall()
                
                for row in result:
                    # Get column count
                    column_count = engine.execute(f"""
                        SELECT COUNT(*) FROM information_schema.columns 
                        WHERE table_schema = 'public' AND table_name = '{row[0]}'
                    """).scalar()
                    
                    # Get index count
                    index_count = engine.execute(f"""
                        SELECT COUNT(*) FROM pg_indexes
                        WHERE schemaname = 'public' AND tablename = '{row[0]}'
                    """).scalar()
                    
                    tables.append({
                        'name': row[0],
                        'row_count': row[1],
                        'column_count': column_count,
                        'index_count': index_count,
                        'size': row[2]
                    })
            elif engine.name == 'mysql':
                # Get tables with row counts and sizes
                db_name = engine.url.database
                result = engine.execute(f"""
                    SELECT 
                        TABLE_NAME, 
                        TABLE_ROWS,
                        ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS size_mb
                    FROM information_schema.TABLES 
                    WHERE TABLE_SCHEMA = '{db_name}'
                    ORDER BY TABLE_NAME
                """).fetchall()
                
                for row in result:
                    # Get column count
                    column_count = engine.execute(f"""
                        SELECT COUNT(*) FROM information_schema.columns 
                        WHERE table_schema = '{db_name}' AND table_name = '{row[0]}'
                    """).scalar()
                    
                    # Get index count
                    index_count = engine.execute(f"""
                        SELECT COUNT(*) FROM information_schema.statistics
                        WHERE table_schema = '{db_name}' AND table_name = '{row[0]}'
                    """).scalar()
                    
                    tables.append({
                        'name': row[0],
                        'row_count': row[1],
                        'column_count': column_count,
                        'index_count': index_count,
                        'size': f"{row[2]} MB"
                    })
            
            return jsonify({'tables': tables})
        
        # Fallback to basic information if SQLAlchemy is not available
        # Try to detect SQLite database
        app_dir = os.path.dirname(os.path.abspath(current_app.root_path))
        db_path = None
        
        # Check common database paths
        common_paths = [
            os.path.join(app_dir, 'instance', 'app.db'),
            os.path.join(app_dir, 'app.db'),
            os.path.join(app_dir, 'site.db'),
            os.path.join(app_dir, 'database.db')
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                db_path = path
                break
        
        if db_path:
            conn = sqlite3.connect(db_path)
            
            tables = []
            
            # Get table list
            table_list = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            
            for table_name in [row[0] for row in table_list]:
                # Skip SQLite system tables
                if table_name.startswith('sqlite_'):
                    continue
                
                # Get row count
                row_count = conn.execute(f"SELECT COUNT(*) FROM '{table_name}'").fetchone()[0]
                
                # Get column info
                columns = conn.execute(f"PRAGMA table_info('{table_name}')").fetchall()
                column_count = len(columns)
                
                # Get index info
                indices = conn.execute(f"PRAGMA index_list('{table_name}')").fetchall()
                index_count = len(indices)
                
                tables.append({
                    'name': table_name,
                    'row_count': row_count,
                    'column_count': column_count,
                    'index_count': index_count
                })
            
            conn.close()
            
            return jsonify({'tables': tables})
        
        return jsonify({
            'error': 'Could not detect database tables. Please customize this endpoint for your specific database.'
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/application/info', methods=['GET'])
def application_info():
    try:
        # Get Flask app info
        flask_version = current_app.config.get('FLASK_VERSION', 'Unknown')
        if flask_version == 'Unknown':
            try:
                import flask
                flask_version = flask.__version__
            except:
                pass
        
        # Get Python version
        python_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        
        # Get runtime information
        runtime_info = {
            'start_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(request_stats['start_time'])),
            'uptime_seconds': time.time() - request_stats['start_time'],
            'uptime_formatted': format_uptime(time.time() - request_stats['start_time']),
            'threads': threading.active_count(),
            'current_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
        }
        
        # Get application config (excluding sensitive info)
        safe_config = {}
        sensitive_keys = ['SECRET_KEY', 'PASSWORD', 'TOKEN', 'KEY', 'SALT', 'AUTH', 'SECURITY']
        
        for key, value in current_app.config.items():
            # Skip sensitive data
            if any(sensitive in key.upper() for sensitive in sensitive_keys):
                safe_config[key] = '******'
            else:
                # Convert non-serializable types to strings
                try:
                    json.dumps({key: value})
                    safe_config[key] = value
                except:
                    safe_config[key] = str(value)
        
        return jsonify({
            'name': current_app.name,
            'environment': current_app.config.get('ENV', 'production'),
            'debug': current_app.debug,
            'testing': current_app.testing,
            'flask_version': flask_version,
            'python_version': python_version,
            'runtime': runtime_info,
            'config': safe_config
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/application/users', methods=['GET'])
def application_users():
    try:
        # Try to get user model and information if SQLAlchemy is available
        users = []
        user_count = 0
        active_users = 0
        
        if hasattr(current_app, 'extensions') and 'sqlalchemy' in current_app.extensions:
            db = current_app.extensions['sqlalchemy'].db
            
            # Try to find a User model
            User = None
            for attr in dir(db.Model):
                model = getattr(db.Model, attr)
                if hasattr(model, '__tablename__') and getattr(model, '__tablename__') in ['user', 'users', 'auth_user']:
                    User = model
                    break
            
            if User:
                # Try common field names
                id_field = next((field for field in ['id', 'user_id', 'uid'] if hasattr(User, field)), None)
                username_field = next((field for field in ['username', 'user_name', 'login', 'email'] if hasattr(User, field)), None)
                active_field = next((field for field in ['active', 'is_active', 'enabled', 'is_enabled'] if hasattr(User, field)), None)
                created_field = next((field for field in ['created_at', 'date_joined', 'created', 'join_date'] if hasattr(User, field)), None)
                last_login_field = next((field for field in ['last_login', 'last_login_at', 'last_seen'] if hasattr(User, field)), None)
                
                # Get total user count
                user_count = db.session.query(User).count()
                
                # Get active user count if field exists
                if active_field:
                    active_users = db.session.query(User).filter(getattr(User, active_field) == True).count()
                
                # Get most recent users
                recent_users_query = db.session.query(User)
                if created_field:
                    recent_users_query = recent_users_query.order_by(getattr(User, created_field).desc())
                
                # Get the 10 most recent users
                recent_users = recent_users_query.limit(10).all()
                
                # Format user data
                for user in recent_users:
                    user_data = {
                        'id': getattr(user, id_field) if id_field else 'Unknown',
                        'username': getattr(user, username_field) if username_field else 'Unknown',
                        'active': getattr(user, active_field) if active_field else 'Unknown',
                        'created': str(getattr(user, created_field)) if created_field else 'Unknown',
                        'last_login': str(getattr(user, last_login_field)) if last_login_field and getattr(user, last_login_field) else 'Never'
                    }
                    users.append(user_data)
        
        return jsonify({
            'total_users': user_count,
            'active_users': active_users,
            'recent_users': users
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/application/requests', methods=['GET'])
def application_requests():
    try:
        # Calculate average response time
        avg_response_time = sum(request_stats['response_times']) / len(request_stats['response_times']) if request_stats['response_times'] else 0
        
        # Get frequently accessed routes
        top_routes = sorted(request_stats['routes'].items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Format request history
        formatted_history = []
        for req in request_history:
            formatted_history.append({
                'id': req['id'],
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(req['timestamp'])),
                'path': req['path'],
                'method': req['method'],
                'status_code': req['status_code'],
                'ip': req['ip'],
                'duration': f"{req['duration'] * 1000:.2f} ms",
                'user_agent': req['user_agent'],
                'user_id': req['user_id']
            })
        
        return jsonify({
            'total_requests': request_stats['count'],
            'request_rate': request_stats['count'] / (time.time() - request_stats['start_time']),
            'avg_response_time': avg_response_time,
            'status_codes': dict(request_stats['status_codes']),
            'methods': dict(request_stats['methods']),
            'top_routes': dict(top_routes),
            'recent_requests': formatted_history
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/application/routes', methods=['GET'])
def application_routes():
    try:
        routes = []
        
        for rule in current_app.url_map.iter_rules():
            # Skip the static route
            if rule.endpoint == 'static':
                continue
                
            methods = list(rule.methods - {'HEAD', 'OPTIONS'})
            route = {
                'endpoint': rule.endpoint,
                'methods': methods,
                'path': str(rule),
                'arguments': list(rule.arguments)
            }
            routes.append(route)
        
        # Sort routes by path
        routes.sort(key=lambda x: x['path'])
        
        return jsonify({
            'total_routes': len(routes),
            'routes': routes
        })
    except Exception as e:
        return jsonify({'error': str(e)})
    
@monitoring_bp.route('/logs/error', methods=['GET'])
def error_logs():
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 100, type=int)
        search = request.args.get('search', None)
        
        # Try to find error log file
        log_paths = []
        
        # Check common log file locations
        common_log_paths = [
            '/var/log/apache2/error.log',
            '/var/log/nginx/error.log',
            '/var/log/httpd/error_log',
            '/var/log/flask/error.log',
            './logs/error.log',
            './error.log',
            './log/error.log',
            os.path.join(current_app.root_path, 'logs', 'error.log'),
            os.path.join(current_app.root_path, 'log', 'error.log'),
            os.path.join(current_app.root_path, 'error.log')
        ]
        
        # Check for application-specific logs based on app name
        if current_app.name:
            common_log_paths.extend([
                f'/var/log/{current_app.name}/error.log',
                f'./logs/{current_app.name}_error.log',
                f'./log/{current_app.name}_error.log',
                os.path.join(current_app.root_path, 'logs', f'{current_app.name}_error.log'),
                os.path.join(current_app.root_path, 'log', f'{current_app.name}_error.log')
            ])
        
        # Add any .log files in the logs directory that contain "error"
        log_dirs = [
            '/var/log/',
            './logs/',
            './log/',
            os.path.join(current_app.root_path, 'logs'),
            os.path.join(current_app.root_path, 'log')
        ]
        
        for log_dir in log_dirs:
            if os.path.exists(log_dir) and os.path.isdir(log_dir):
                error_log_files = glob.glob(os.path.join(log_dir, '*error*.log'))
                log_paths.extend(error_log_files)
        
        # Add all possible paths, we'll check for existence later
        log_paths.extend(common_log_paths)
        
        # Remove duplicates and filter to existing files
        unique_log_paths = []
        for path in log_paths:
            if path not in unique_log_paths and os.path.exists(path) and os.path.isfile(path):
                unique_log_paths.append(path)
        
        # If no log files found, try to get logs from app.logger
        if not unique_log_paths and hasattr(current_app, 'logger'):
            # Check if the logger has a FileHandler
            log_content = []
            log_file = None
            
            for handler in current_app.logger.handlers:
                if hasattr(handler, 'baseFilename'):
                    log_file = handler.baseFilename
                    if os.path.exists(log_file):
                        unique_log_paths.append(log_file)
                        break
        
        # Process log files
        logs = []
        total_lines = 0
        
        if unique_log_paths:
            # Use the first log file found
            log_file = unique_log_paths[0]
            
            # Read the log file
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.readlines()
            
            # Filter by search term if provided
            if search:
                log_content = [line for line in log_content if search.lower() in line.lower()]
            
            total_lines = len(log_content)
            
            # Calculate pagination
            start_line = (page - 1) * per_page
            end_line = start_line + per_page
            
            # Slice the log content for the current page
            page_content = log_content[start_line:end_line]
            
            # Parse and format log entries
            for line in page_content:
                # Try to parse common log formats
                log_entry = parse_log_line(line)
                logs.append(log_entry)
            
            # Reverse the logs to show newest first
            logs.reverse()
        
        return jsonify({
            'logs': logs,
            'total_lines': total_lines,
            'current_page': page,
            'total_pages': (total_lines + per_page - 1) // per_page,
            'per_page': per_page,
            'log_file': unique_log_paths[0] if unique_log_paths else None,
            'available_log_files': unique_log_paths
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/logs/access', methods=['GET'])
def access_logs():
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 100, type=int)
        search = request.args.get('search', None)
        
        # Try to find access log file
        log_paths = []
        
        # Check common log file locations
        common_log_paths = [
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/var/log/httpd/access_log',
            '/var/log/flask/access.log',
            './logs/access.log',
            './access.log',
            './log/access.log',
            os.path.join(current_app.root_path, 'logs', 'access.log'),
            os.path.join(current_app.root_path, 'log', 'access.log'),
            os.path.join(current_app.root_path, 'access.log')
        ]
        
        # Check for application-specific logs based on app name
        if current_app.name:
            common_log_paths.extend([
                f'/var/log/{current_app.name}/access.log',
                f'./logs/{current_app.name}_access.log',
                f'./log/{current_app.name}_access.log',
                os.path.join(current_app.root_path, 'logs', f'{current_app.name}_access.log'),
                os.path.join(current_app.root_path, 'log', f'{current_app.name}_access.log')
            ])
        
        # Add any .log files in the logs directory that contain "access"
        log_dirs = [
            '/var/log/',
            './logs/',
            './log/',
            os.path.join(current_app.root_path, 'logs'),
            os.path.join(current_app.root_path, 'log')
        ]
        
        for log_dir in log_dirs:
            if os.path.exists(log_dir) and os.path.isdir(log_dir):
                access_log_files = glob.glob(os.path.join(log_dir, '*access*.log'))
                log_paths.extend(access_log_files)
        
        # Add all possible paths, we'll check for existence later
        log_paths.extend(common_log_paths)
        
        # Remove duplicates and filter to existing files
        unique_log_paths = []
        for path in log_paths:
            if path not in unique_log_paths and os.path.exists(path) and os.path.isfile(path):
                unique_log_paths.append(path)
        
        # Process log files
        logs = []
        total_lines = 0
        
        if unique_log_paths:
            # Use the first log file found
            log_file = unique_log_paths[0]
            
            # Read the log file
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.readlines()
            
            # Filter by search term if provided
            if search:
                log_content = [line for line in log_content if search.lower() in line.lower()]
            
            total_lines = len(log_content)
            
            # Calculate pagination
            start_line = (page - 1) * per_page
            end_line = start_line + per_page
            
            # Slice the log content for the current page
            page_content = log_content[start_line:end_line]
            
            # Parse and format log entries
            for line in page_content:
                # Try to parse common log formats
                log_entry = parse_access_log_line(line)
                logs.append(log_entry)
            
            # Reverse the logs to show newest first
            logs.reverse()
        else:
            # If no access log file found, use the request history as a fallback
            logs = []
            for req in list(request_history):
                logs.append({
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(req['timestamp'])),
                    'ip': req['ip'],
                    'method': req['method'],
                    'path': req['path'],
                    'status': req['status_code'],
                    'user_agent': req['user_agent'],
                    'duration': f"{req['duration'] * 1000:.2f} ms",
                    'raw': f"{req['ip']} - - [{time.strftime('%d/%b/%Y:%H:%M:%S', time.localtime(req['timestamp']))} +0000] \"{req['method']} {req['path']} HTTP/1.1\" {req['status_code']} - \"{req['user_agent']}\""
                })
            
            # Filter by search term if provided
            if search:
                logs = [log for log in logs if search.lower() in str(log).lower()]
            
            total_lines = len(logs)
            
            # Calculate pagination
            start_line = (page - 1) * per_page
            end_line = start_line + per_page
            
            # Slice the logs for the current page
            logs = logs[start_line:end_line]
            
            # Reverse the logs to show newest first
            logs.reverse()
        
        return jsonify({
            'logs': logs,
            'total_lines': total_lines,
            'current_page': page,
            'total_pages': (total_lines + per_page - 1) // per_page,
            'per_page': per_page,
            'log_file': unique_log_paths[0] if unique_log_paths else 'Using request history',
            'available_log_files': unique_log_paths
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# Helper function to parse log lines
def parse_log_line(line):
    # Try to detect log format and parse it
    # Default structure if we can't parse
    log_entry = {
        'timestamp': None,
        'level': None,
        'message': line.strip(),
        'raw': line.strip()
    }
    
    # Try to parse common log formats
    
    # 1. Try to parse standard Python logging format: YYYY-MM-DD HH:MM:SS,MS - Level - Message
    python_log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - (\w+) - (.+)'
    match = re.match(python_log_pattern, line)
    if match:
        log_entry['timestamp'] = match.group(1)
        log_entry['level'] = match.group(2)
        log_entry['message'] = match.group(3).strip()
        return log_entry
    
    # 2. Try Flask's default error log format: YYYY-MM-DD HH:MM:SS,MS Level: Message
    flask_log_pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) (\w+): (.+)'
    match = re.match(flask_log_pattern, line)
    if match:
        log_entry['timestamp'] = match.group(1)
        log_entry['level'] = match.group(2)
        log_entry['message'] = match.group(3).strip()
        return log_entry
    
    # 3. Try Apache/Nginx error log format: [Day Month DD HH:MM:SS.UUUUUU YYYY] [Level] Message
    apache_log_pattern = r'\[(\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] \[(\w+)\] (.+)'
    match = re.match(apache_log_pattern, line)
    if match:
        log_entry['timestamp'] = match.group(1)
        log_entry['level'] = match.group(2)
        log_entry['message'] = match.group(3).strip()
        return log_entry
    
    # 4. Try to extract just a timestamp and message
    timestamp_pattern = r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[,\.]\d+)?(?:\s[\+\-]\d{4})?)(.+)'
    match = re.match(timestamp_pattern, line)
    if match:
        log_entry['timestamp'] = match.group(1)
        log_entry['message'] = match.group(2).strip()
        
        # Try to extract log level from the message
        level_pattern = r'^(?:\[(\w+)\]|\s(\w+)\s|(\w+):)'
        level_match = re.match(level_pattern, match.group(2))
        if level_match:
            level = next((g for g in level_match.groups() if g), None)
            if level:
                log_entry['level'] = level
                log_entry['message'] = re.sub(level_pattern, '', match.group(2)).strip()
        
        return log_entry
    
    return log_entry

def parse_access_log_line(line):
    # Try to detect access log format and parse it
    # Default structure if we can't parse
    log_entry = {
        'timestamp': None,
        'ip': None,
        'method': None,
        'path': None,
        'status': None,
        'size': None,
        'user_agent': None,
        'raw': line.strip()
    }
    
    # Common Log Format (CLF)
    # 127.0.0.1 - - [09/Mar/2025:10:15:40 +0000] "GET /api/monitoring


@monitoring_bp.route('/network/interfaces', methods=['GET'])
def network_interfaces():
    try:
        interfaces = {}
        
        # Get address information for all network interfaces
        addrs = psutil.net_if_addrs()
        
        # Get statistics for all network interfaces
        stats = psutil.net_if_stats()
        
        for interface_name, addr_list in addrs.items():
            # Skip loopback interfaces if they're not the only ones
            if interface_name.startswith('lo') and len(addrs) > 1:
                continue
                
            interface_info = {
                'addresses': [],
                'stats': {},
                'is_up': False
            }
            
            # Add address information
            for addr in addr_list:
                address_info = {
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast,
                    'ptp': addr.ptp
                }
                
                # Add friendly family name
                if addr.family == socket.AF_INET:
                    address_info['family_name'] = 'IPv4'
                elif addr.family == socket.AF_INET6:
                    address_info['family_name'] = 'IPv6'
                elif addr.family == psutil.AF_LINK:
                    address_info['family_name'] = 'MAC'
                else:
                    address_info['family_name'] = f'Unknown ({addr.family})'
                
                interface_info['addresses'].append(address_info)
            
            # Add interface statistics
            if interface_name in stats:
                stat = stats[interface_name]
                interface_info['stats'] = {
                    'isup': stat.isup,
                    'duplex': str(stat.duplex),
                    'speed': stat.speed,
                    'mtu': stat.mtu
                }
                interface_info['is_up'] = stat.isup
            
            interfaces[interface_name] = interface_info
        
        return jsonify({
            'interfaces': interfaces,
            'count': len(interfaces),
            'default_gateway': get_default_gateway()
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/network/traffic', methods=['GET'])
def network_traffic():
    try:
        # Get current network I/O counters
        current_net_io = psutil.net_io_counters(pernic=True)
        
        # Store timestamps for calculating rates
        timestamp = time.time()
        
        # If we have previous measurements, calculate rates
        network_data = {}
        
        # Get all network interfaces
        for interface, counters in current_net_io.items():
            # Skip loopback interfaces if they're not the only ones
            if interface.startswith('lo') and len(current_net_io) > 1:
                continue
                
            network_data[interface] = {
                'bytes_sent': counters.bytes_sent,
                'bytes_recv': counters.bytes_recv,
                'packets_sent': counters.packets_sent,
                'packets_recv': counters.packets_recv,
                'errin': counters.errin,
                'errout': counters.errout,
                'dropin': counters.dropin,
                'dropout': counters.dropout,
                'formatted': {
                    'bytes_sent': format_bytes(counters.bytes_sent),
                    'bytes_recv': format_bytes(counters.bytes_recv)
                }
            }
        
        # Get total network I/O
        total_io = psutil.net_io_counters()
        
        total_data = {
            'bytes_sent': total_io.bytes_sent,
            'bytes_recv': total_io.bytes_recv,
            'packets_sent': total_io.packets_sent,
            'packets_recv': total_io.packets_recv,
            'errin': total_io.errin,
            'errout': total_io.errout,
            'dropin': total_io.dropin,
            'dropout': total_io.dropout,
            'formatted': {
                'bytes_sent': format_bytes(total_io.bytes_sent),
                'bytes_recv': format_bytes(total_io.bytes_recv)
            }
        }
        
        return jsonify({
            'interfaces': network_data,
            'total': total_data
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/network/connections', methods=['GET'])
def network_connections():
    try:
        connections_list = []
        
        # Get all network connections
        for conn in psutil.net_connections(kind='all'):
            try:
                # Get process info if pid is available
                process_name = 'Unknown'
                if conn.pid:
                    try:
                        process = psutil.Process(conn.pid)
                        process_name = process.name()
                    except:
                        pass
                
                # Format local and remote addresses
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "None"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "None"
                
                connections_list.append({
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.type,
                    'laddr': laddr,
                    'raddr': raddr,
                    'status': conn.status,
                    'pid': conn.pid,
                    'process': process_name
                })
            except:
                # Skip connections that can't be processed
                continue
        
        # Group connections by status
        status_counts = {}
        for conn in connections_list:
            status = conn.get('status', 'UNKNOWN')
            if status in status_counts:
                status_counts[status] += 1
            else:
                status_counts[status] = 1
        
        # Group connections by process
        process_counts = {}
        for conn in connections_list:
            process = conn.get('process', 'Unknown')
            if process in process_counts:
                process_counts[process] += 1
            else:
                process_counts[process] = 1
        
        return jsonify({
            'connections': connections_list,
            'total': len(connections_list),
            'status_counts': status_counts,
            'process_counts': process_counts
        })
    except Exception as e:
        return jsonify({'error': str(e)})
    
# Disk Endpoints
@monitoring_bp.route('/disk/partitions')
def disk_partitions():
    try:
        partitions = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                partition_info = {
                    'device': part.device,
                    'mountpoint': part.mountpoint,
                    'fstype': part.fstype,
                    'opts': part.opts,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': usage.percent,
                    'total_formatted': format_bytes(usage.total),
                    'used_formatted': format_bytes(usage.used),
                    'free_formatted': format_bytes(usage.free)
                }
                partitions.append(partition_info)
            except (PermissionError, FileNotFoundError):
                # Some mountpoints might not be accessible
                pass
        
        return jsonify({'partitions': partitions})
    except Exception as e:
        return jsonify({'error': str(e)})

@monitoring_bp.route('/disk/io')
def disk_io():
    try:
        io_counters = psutil.disk_io_counters(perdisk=True)
        formatted_io = {}
        
        for disk, counters in io_counters.items():
            formatted_io[disk] = {
                'read_count': counters.read_count,
                'write_count': counters.write_count,
                'read_bytes': counters.read_bytes,
                'write_bytes': counters.write_bytes,
                'read_time': counters.read_time,
                'write_time': counters.write_time,
                'read_bytes_formatted': format_bytes(counters.read_bytes),
                'write_bytes_formatted': format_bytes(counters.write_bytes)
            }
        
        return jsonify({'io_counters': formatted_io})
    except Exception as e:
        return jsonify({'error': str(e)})


# Helper function to get default gateway - updated for Windows compatibility
def get_default_gateway():
    try:
        # Try different approaches to get the default gateway
        # Method 1: Use psutil if it has the function
        if hasattr(psutil, 'net_if_default_gateway'):
            gateways = psutil.net_if_default_gateway()
            if gateways:
                # Return the first gateway found
                for interface, gateway in gateways.items():
                    return {'interface': interface, 'gateway': gateway}
        
        # Method 2: Parse route information on Linux
        if os.path.exists('/proc/net/route'):
            with open('/proc/net/route') as f:
                for line in f.readlines():
                    fields = line.strip().split()
                    if fields[1] == '00000000' and int(fields[3], 16) & 2:
                        # Convert the gateway IP from hex to decimal notation
                        gateway = socket.inet_ntoa(bytes.fromhex(fields[2].zfill(8))[::-1])
                        return {'interface': fields[0], 'gateway': gateway}
        
        # Method 3: Windows-specific approach using 'route print' command
        if platform.system() == 'Windows':
            try:
                output = os.popen('route print 0.0.0.0').read()
                for line in output.split('\n'):
                    line = line.strip()
                    if '0.0.0.0' in line and not line.startswith('Network Destination'):
                        parts = line.split()
                        if len(parts) >= 4:
                            # Format of route print output: Network Destination, Netmask, Gateway, Interface, Metric
                            # The gateway is usually the 3rd column
                            return {'interface': 'Default', 'gateway': parts[2]}
            except:
                pass
        
        # Method 4: Linux-specific approach using 'ip route' command
        if platform.system() == 'Linux':
            try:
                output = os.popen('ip route show default').read()
                if output:
                    # Parse the default route line
                    # Format: default via 192.168.1.1 dev eth0 proto dhcp
                    parts = output.strip().split()
                    if len(parts) >= 5 and parts[0] == 'default' and parts[1] == 'via':
                        return {'interface': parts[4], 'gateway': parts[2]}
            except:
                pass
        
        # If we couldn't determine the gateway
        return {'interface': 'Unknown', 'gateway': 'Unknown'}
    except Exception as e:
        return {'interface': 'Unknown', 'gateway': 'Unknown', 'error': str(e)}


# Helper function to format uptime
def format_uptime(seconds):
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    return f"{int(days)} days, {int(hours)} hours, {int(minutes)} minutes, {int(seconds)} seconds"


# Helper function to format bytes to human-readable format
def format_bytes(bytes_value):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.2f} PB"
