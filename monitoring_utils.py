import psutil
import platform
import time
import datetime
import os
import sqlite3
import json
from flask import current_app
import logging
import socket
import subprocess

class SystemMonitor:
    """Utilities for monitoring system resources and performance"""
    
    @staticmethod
    def get_system_info():
        """Get basic system information"""
        try:
            info = {
                'system': platform.system(),
                'node': platform.node(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
                'uptime_seconds': int(time.time() - psutil.boot_time())
            }
            
            # Format uptime nicely
            uptime = info['uptime_seconds']
            days, remainder = divmod(uptime, 86400)
            hours, remainder = divmod(remainder, 3600)
            minutes, seconds = divmod(remainder, 60)
            info['uptime_formatted'] = f"{days}d {hours}h {minutes}m {seconds}s"
            
            return info
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_cpu_info():
        """Get CPU information and usage"""
        try:
            cpu_info = {
                'physical_cores': psutil.cpu_count(logical=False),
                'total_cores': psutil.cpu_count(logical=True),
                'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else "N/A",
                'min_frequency': psutil.cpu_freq().min if psutil.cpu_freq() else "N/A",
                'max_frequency': psutil.cpu_freq().max if psutil.cpu_freq() else "N/A",
                'usage_percent': psutil.cpu_percent(interval=0.5, percpu=False),
                'per_cpu_percent': psutil.cpu_percent(interval=0.5, percpu=True),
                'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else "N/A"
            }
            
            return cpu_info
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_memory_info():
        """Get memory usage information"""
        try:
            virtual_mem = psutil.virtual_memory()
            swap_mem = psutil.swap_memory()
            
            memory_info = {
                'virtual': {
                    'total': virtual_mem.total,
                    'available': virtual_mem.available,
                    'used': virtual_mem.used,
                    'percent': virtual_mem.percent,
                    'formatted': {
                        'total': SystemMonitor._format_bytes(virtual_mem.total),
                        'available': SystemMonitor._format_bytes(virtual_mem.available),
                        'used': SystemMonitor._format_bytes(virtual_mem.used)
                    }
                },
                'swap': {
                    'total': swap_mem.total,
                    'used': swap_mem.used,
                    'free': swap_mem.free,
                    'percent': swap_mem.percent,
                    'formatted': {
                        'total': SystemMonitor._format_bytes(swap_mem.total),
                        'used': SystemMonitor._format_bytes(swap_mem.used),
                        'free': SystemMonitor._format_bytes(swap_mem.free)
                    }
                }
            }
            
            return memory_info
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_disk_info():
        """Get disk usage information"""
        try:
            disk_info = []
            partitions = psutil.disk_partitions()
            
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    partition_info = {
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'opts': partition.opts,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent,
                        'formatted': {
                            'total': SystemMonitor._format_bytes(usage.total),
                            'used': SystemMonitor._format_bytes(usage.used),
                            'free': SystemMonitor._format_bytes(usage.free)
                        }
                    }
                    disk_info.append(partition_info)
                except PermissionError:
                    # Some mountpoints may not be accessible
                    continue
            
            # Get disk I/O statistics
            disk_io = psutil.disk_io_counters(perdisk=False)
            if disk_io:
                io_stats = {
                    'read_count': disk_io.read_count,
                    'write_count': disk_io.write_count,
                    'read_bytes': disk_io.read_bytes,
                    'write_bytes': disk_io.write_bytes,
                    'formatted': {
                        'read_bytes': SystemMonitor._format_bytes(disk_io.read_bytes),
                        'write_bytes': SystemMonitor._format_bytes(disk_io.write_bytes)
                    }
                }
            else:
                io_stats = None
                
            return {
                'partitions': disk_info,
                'io_stats': io_stats
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_network_info():
        """Get network interface and connection information"""
        try:
            interfaces = []
            net_io = psutil.net_io_counters(pernic=True)
            net_if_addrs = psutil.net_if_addrs()
            
            for interface_name, addresses in net_if_addrs.items():
                interface_info = {
                    'name': interface_name,
                    'addresses': [],
                    'stats': None
                }
                
                for addr in addresses:
                    addr_info = {
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    }
                    interface_info['addresses'].append(addr_info)
                
                # Add IO statistics if available
                if interface_name in net_io:
                    stats = net_io[interface_name]
                    interface_info['stats'] = {
                        'bytes_sent': stats.bytes_sent,
                        'bytes_recv': stats.bytes_recv,
                        'packets_sent': stats.packets_sent,
                        'packets_recv': stats.packets_recv,
                        'errin': stats.errin,
                        'errout': stats.errout,
                        'dropin': stats.dropin,
                        'dropout': stats.dropout,
                        'formatted': {
                            'bytes_sent': SystemMonitor._format_bytes(stats.bytes_sent),
                            'bytes_recv': SystemMonitor._format_bytes(stats.bytes_recv)
                        }
                    }
                
                interfaces.append(interface_info)
            
            # Get active connections
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                conn_info = {
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.type,
                    'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                }
                connections.append(conn_info)
                
            return {
                'interfaces': interfaces,
                'connections': connections
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_process_info(limit=20):
        """Get information about running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'create_time', 'status']):
                try:
                    process_info = proc.info
                    process_info['memory_info'] = proc.memory_info()._asdict() if proc.memory_info() else None
                    if process_info['memory_info']:
                        process_info['memory_info']['formatted'] = {
                            'rss': SystemMonitor._format_bytes(process_info['memory_info']['rss']),
                            'vms': SystemMonitor._format_bytes(process_info['memory_info']['vms'])
                        }
                    process_info['formatted_create_time'] = datetime.datetime.fromtimestamp(process_info['create_time']).strftime('%Y-%m-%d %H:%M:%S') if process_info['create_time'] else None
                    
                    processes.append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Sort by memory percent usage (descending)
            processes.sort(key=lambda x: x['memory_percent'] if x['memory_percent'] else 0, reverse=True)
            
            return processes[:limit]
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def ping_host(host, count=4):
        """Ping a host and get response times"""
        try:
            if platform.system().lower() == "windows":
                output = subprocess.check_output(f"ping -n {count} {host}", shell=True).decode("utf-8")
            else:
                output = subprocess.check_output(f"ping -c {count} {host}", shell=True).decode("utf-8")
                
            # Parse ping results
            lines = output.split('\n')
            times = []
            
            for line in lines:
                if "time=" in line or "time<" in line:
                    try:
                        time_part = line.split("time=")[1].split()[0] if "time=" in line else line.split("time<")[1].split()[0]
                        time_value = float(time_part.replace("ms", ""))
                        times.append(time_value)
                    except:
                        pass
            
            if times:
                return {
                    'host': host,
                    'successful': True,
                    'min': min(times),
                    'max': max(times),
                    'avg': sum(times) / len(times),
                    'packet_loss': count - len(times)
                }
            else:
                return {
                    'host': host,
                    'successful': False,
                    'error': 'Could not parse ping response times'
                }
                
        except Exception as e:
            return {
                'host': host,
                'successful': False,
                'error': str(e)
            }
    
    @staticmethod
    def _format_bytes(bytes, precision=2):
        """Format bytes to human-readable format"""
        if bytes < 0:
            bytes = 0
            
        suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
        suffix_index = 0
        
        while bytes >= 1024 and suffix_index < len(suffixes) - 1:
            bytes /= 1024
            suffix_index += 1
            
        return f"{bytes:.{precision}f} {suffixes[suffix_index]}"

class DatabaseMonitor:
    """Utilities for monitoring database performance and metrics"""
    
    @staticmethod
    def get_database_info(db_path):
        """Get basic information about the SQLite database"""
        try:
            db_info = {
                'path': db_path,
                'exists': os.path.exists(db_path),
                'size': os.path.getsize(db_path) if os.path.exists(db_path) else 0,
                'formatted_size': SystemMonitor._format_bytes(os.path.getsize(db_path)) if os.path.exists(db_path) else "0 B",
                'last_modified': datetime.datetime.fromtimestamp(os.path.getmtime(db_path)).strftime('%Y-%m-%d %H:%M:%S') if os.path.exists(db_path) else None
            }
            
            return db_info
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_table_info(db_path):
        """Get information about tables in the database"""
        try:
            if not os.path.exists(db_path):
                return {'error': 'Database file does not exist'}
                
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get list of tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            table_info = []
            
            for table in tables:
                table_name = table[0]
                
                # Get table schema
                cursor.execute(f"PRAGMA table_info({table_name})")
                columns = cursor.fetchall()
                
                # Get row count
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                row_count = cursor.fetchone()[0]
                
                # Get approximate size
                size_query = f"""
                WITH RECURSIVE
                  cnt(x) AS (
                     SELECT 1
                     UNION ALL
                     SELECT x+1 FROM cnt
                      LIMIT (SELECT COUNT(*) FROM {table_name})
                  ),
                  sizes(s) AS (
                     SELECT total(length(quote({table_name}))) FROM {table_name}
                  )
                SELECT s FROM sizes LIMIT 1
                """
                
                try:
                    cursor.execute(size_query)
                    size_result = cursor.fetchone()
                    approx_size = size_result[0] if size_result else 0
                except:
                    approx_size = 0
                
                table_data = {
                    'name': table_name,
                    'columns': [{'cid': col[0], 'name': col[1], 'type': col[2], 'notnull': col[3], 'default_value': col[4], 'pk': col[5]} for col in columns],
                                        'row_count': row_count,
                    'approx_size': approx_size,
                    'formatted_size': SystemMonitor._format_bytes(approx_size)
                }
                
                table_info.append(table_data)
            
            conn.close()
            
            return table_info
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_database_stats(db_path):
        """Get database statistics"""
        try:
            if not os.path.exists(db_path):
                return {'error': 'Database file does not exist'}
                
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get database statistics from SQLite
            cursor.execute("PRAGMA stats")
            stats_rows = cursor.fetchall()
            
            # Get database integrity check
            cursor.execute("PRAGMA integrity_check")
            integrity = cursor.fetchone()[0]
            
            # Get database page size and cache size
            cursor.execute("PRAGMA page_size")
            page_size = cursor.fetchone()[0]
            
            cursor.execute("PRAGMA cache_size")
            cache_size = cursor.fetchone()[0]
            
            stats = {
                'stats': [dict(zip(['table', 'idx', 'stat', 'value'], row)) for row in stats_rows],
                'integrity': integrity,
                'page_size': page_size,
                'cache_size': cache_size,
                'formatted': {
                    'page_size': SystemMonitor._format_bytes(page_size),
                    'cache_size': SystemMonitor._format_bytes(cache_size * page_size)
                }
            }
            
            conn.close()
            
            return stats
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def execute_query(db_path, query, params=None, explain=False):
        """Execute a SQL query and get results with execution time"""
        try:
            if not os.path.exists(db_path):
                return {'error': 'Database file does not exist'}
                
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            start_time = time.time()
            
            if explain:
                # Get query plan using EXPLAIN QUERY PLAN
                cursor.execute(f"EXPLAIN QUERY PLAN {query}", params or [])
                query_plan = cursor.fetchall()
                
                # Execute the actual query
                cursor.execute(query, params or [])
                results = cursor.fetchall()
            else:
                # Just execute the query
                cursor.execute(query, params or [])
                results = cursor.fetchall()
                query_plan = None
            
            execution_time = time.time() - start_time
            
            # Convert results to list of dicts
            column_names = [column[0] for column in cursor.description]
            results_list = []
            
            for row in results:
                results_list.append(dict(zip(column_names, row)))
            
            query_result = {
                'query': query,
                'execution_time': execution_time,
                'execution_time_ms': round(execution_time * 1000, 2),
                'row_count': len(results_list),
                'results': results_list[:1000],  # Limit results to avoid overwhelming responses
                'truncated': len(results_list) > 1000
            }
            
            if query_plan:
                query_result['query_plan'] = [dict(zip(['id', 'parent', 'detail'], row)) for row in query_plan]
            
            conn.close()
            
            return query_result
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_index_info(db_path):
        """Get information about indexes in the database"""
        try:
            if not os.path.exists(db_path):
                return {'error': 'Database file does not exist'}
                
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Get list of indexes
            cursor.execute("SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index'")
            indexes = cursor.fetchall()
            
            index_info = []
            
            for idx in indexes:
                index_name, table_name, sql = idx
                
                # Get index statistics
                cursor.execute(f"PRAGMA index_info({index_name})")
                columns = cursor.fetchall()
                
                # Get index statistics
                cursor.execute(f"PRAGMA index_xinfo({index_name})")
                extended_info = cursor.fetchall()
                
                index_data = {
                    'name': index_name,
                    'table': table_name,
                    'sql': sql,
                    'columns': [{'seqno': col[0], 'cid': col[1], 'name': col[2]} for col in columns],
                    'extended_info': [{'seqno': col[0], 'cid': col[1], 'name': col[2], 'desc': col[3], 'coll': col[4], 'key': col[5]} for col in extended_info]
                }
                
                index_info.append(index_data)
            
            conn.close()
            
            return index_info
        except Exception as e:
            return {'error': str(e)}

class ApplicationMonitor:
    """Utilities for monitoring application performance and metrics"""
    
    @staticmethod
    def get_application_info(app):
        """Get basic information about the Flask application"""
        try:
            app_info = {
                'name': app.name,
                'debug': app.debug,
                'testing': app.testing,
                'static_folder': app.static_folder,
                'template_folder': app.template_folder,
                'instance_path': app.instance_path,
                'url_map': str(app.url_map),
                'routes': []
            }
            
            # Get routes
            for rule in app.url_map.iter_rules():
                route = {
                    'endpoint': rule.endpoint,
                    'methods': list(rule.methods),
                    'path': str(rule)
                }
                app_info['routes'].append(route)
            
            return app_info
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def start_request_logging():
        """Configure the application to log request information"""
        class RequestLogMiddleware:
            def __init__(self, app):
                self.app = app
                self.request_logs = []
                self.max_logs = 1000  # Limit the number of stored logs
                
            def __call__(self, environ, start_response):
                # Capture request start time
                start_time = time.time()
                
                # Get request info
                path = environ.get('PATH_INFO', '')
                method = environ.get('REQUEST_METHOD', '')
                remote_addr = environ.get('REMOTE_ADDR', '')
                
                # Process the request
                def capturing_start_response(status, headers, exc_info=None):
                    # Capture response status
                    status_code = int(status.split(' ')[0])
                    
                    # Calculate request duration
                    duration = time.time() - start_time
                    
                    # Log the request
                    log_entry = {
                        'timestamp': datetime.datetime.now().isoformat(),
                        'path': path,
                        'method': method,
                        'status': status_code,
                        'duration': duration,
                        'duration_ms': round(duration * 1000, 2),
                        'remote_addr': remote_addr
                    }
                    
                    # Add to circular buffer
                    self.request_logs.append(log_entry)
                    if len(self.request_logs) > self.max_logs:
                        self.request_logs.pop(0)
                    
                    return start_response(status, headers, exc_info)
                
                return self.app(environ, capturing_start_response)
        
        return RequestLogMiddleware
    
    @staticmethod
    def get_recent_requests(middleware_instance, limit=50):
        """Get recent request logs from the middleware"""
        try:
            logs = middleware_instance.request_logs[-limit:] if limit > 0 else middleware_instance.request_logs
            
            # Calculate statistics
            if logs:
                durations = [log['duration'] for log in logs]
                avg_duration = sum(durations) / len(durations)
                max_duration = max(durations)
                
                status_codes = {}
                for log in logs:
                    status = log['status']
                    status_codes[status] = status_codes.get(status, 0) + 1
                    
                stats = {
                    'count': len(logs),
                    'avg_duration': avg_duration,
                    'avg_duration_ms': round(avg_duration * 1000, 2),
                    'max_duration': max_duration,
                    'max_duration_ms': round(max_duration * 1000, 2),
                    'status_codes': status_codes
                }
            else:
                stats = {
                    'count': 0,
                    'avg_duration': 0,
                    'avg_duration_ms': 0,
                    'max_duration': 0,
                    'max_duration_ms': 0,
                    'status_codes': {}
                }
                
            return {
                'logs': logs,
                'stats': stats
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_error_logs(log_file, limit=100):
        """Get recent error logs from the application log file"""
        try:
            if not os.path.exists(log_file):
                return {'error': f'Log file {log_file} does not exist'}
                
            with open(log_file, 'r') as f:
                # Read the last part of the file
                f.seek(0, os.SEEK_END)
                file_size = f.tell()
                
                # Read up to 100KB from the end of the file
                read_size = min(100 * 1024, file_size)
                f.seek(max(0, file_size - read_size), os.SEEK_SET)
                
                # Read lines
                lines = f.readlines()
                
                # Parse log entries (assuming standard logging format)
                logs = []
                for line in reversed(lines):
                    if 'ERROR' in line or 'WARNING' in line:
                        # Simple parsing, adapt to your log format
                        parts = line.split(' - ', 1)
                        if len(parts) >= 2:
                            timestamp = parts[0]
                            message = parts[1].strip()
                            
                            log_entry = {
                                'timestamp': timestamp,
                                'level': 'ERROR' if 'ERROR' in line else 'WARNING',
                                'message': message
                            }
                            
                            logs.append(log_entry)
                            
                            if len(logs) >= limit:
                                break
                
                return {'logs': logs, 'count': len(logs)}
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_active_users(session_data, minutes=15):
        """Get information about active users in the last X minutes"""
        try:
            active_users = []
            now = datetime.datetime.now()
            active_threshold = now - datetime.timedelta(minutes=minutes)
            
            for session_id, session in session_data.items():
                last_activity = session.get('last_activity')
                if last_activity:
                    # Convert timestamp to datetime
                    last_activity_time = datetime.datetime.fromtimestamp(last_activity)
                    
                    if last_activity_time >= active_threshold:
                        user_info = {
                            'session_id': session_id,
                            'user_id': session.get('user_id'),
                            'username': session.get('username'),
                            'last_activity': last_activity_time.isoformat(),
                            'last_page': session.get('last_page'),
                            'ip_address': session.get('ip_address')
                        }
                        active_users.append(user_info)
            
            return {
                'active_users': active_users,
                'count': len(active_users),
                'time_window': f"{minutes} minutes"
            }
        except Exception as e:
            return {'error': str(e)}

