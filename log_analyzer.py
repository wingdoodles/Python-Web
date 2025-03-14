import re
import json
import datetime
import os
from collections import Counter, defaultdict
from pygrok import Grok
import pandas as pd
import numpy as np
from dateutil import parser

class LogAnalyzer:
    """Core class for log analysis functionality"""
    def __init__(self):
        # Common log format patterns
        self.log_patterns = {
            'apache': '%{COMMONAPACHELOG}',
            'syslog': '%{SYSLOGLINE}',
            'windows': '%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{DATA:source} %{GREEDYDATA:message}',
            'json': None  # JSON logs are parsed differently
        }

        # We'll create Grok instances when needed, not in the constructor

        # Common regex patterns
        self.regex_patterns = {
            'errors': r'(?i)\b(error|exception|fail|failed|failure)\b',
            'warnings': r'(?i)\b(warning|warn|caution)\b',
            'ip': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'timestamp': r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b'
        }
    def parse_log(self, log_content, format_type='auto', custom_format=None, 
                  extract_timestamp=True, categorize_entries=True, 
                  identify_patterns=True, filter_expr=None):
        """
        Parse log content according to the specified format
        
        Args:
            log_content (str): The log content to parse
            format_type (str): The log format type (auto, apache, syslog, windows, json, custom)
            custom_format (str): Custom format pattern (used when format_type is 'custom')
            extract_timestamp (bool): Whether to extract timestamps
            categorize_entries (bool): Whether to categorize by severity
            identify_patterns (bool): Whether to identify common patterns
            filter_expr (str): Optional filter expression
            
        Returns:
            dict: Parsed log data
        """
        try:
            # Detect format if auto is selected
            if format_type == 'auto':
                format_type = self._detect_format(log_content)
            
            # Parse log entries
            entries = []
            
            # Split log content into lines
            lines = log_content.strip().split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                try:
                    entry = self._parse_line(line, format_type, custom_format)
                    if entry:
                        entries.append(entry)
                except Exception as e:
                    print(f"Error parsing line: {str(e)}")
                    continue
            
            # Apply filtering if specified
            if filter_expr and filter_expr.strip():
                entries = self._filter_entries(entries, filter_expr)
            
            # Generate statistics
            stats = self._generate_statistics(entries) if entries else {}
            
            # Identify patterns if requested
            patterns = []
            if identify_patterns and entries:

                messages = [entry.get('message', '') for entry in entries if entry.get('message')]
                patterns = self._identify_patterns(messages)
            
            return {
                'entries': entries,
                'stats': stats,
                'patterns': patterns
            }
        
        except Exception as e:
            return {'error': f"Failed to parse log: {str(e)}"}
    
    def find_patterns(self, log_content, pattern_type, custom_pattern=None, case_sensitive=False):
        """
        Find specific patterns in log content
        
        Args:
            log_content (str): The log content to search
            pattern_type (str): Type of pattern to find
            custom_pattern (str): Custom regex pattern (used when pattern_type is 'custom')
            case_sensitive (bool): Whether to use case-sensitive matching
            
        Returns:
            dict: Found patterns
        """
        try:
            # Determine the pattern to use
            if pattern_type == 'custom' and custom_pattern:
                pattern = custom_pattern
            elif pattern_type in self.regex_patterns:
                pattern = self.regex_patterns[pattern_type]
            else:
                return {'error': 'Invalid pattern type'}
            
            # Compile regex
            flags = 0 if case_sensitive else re.IGNORECASE
            regex = re.compile(pattern, flags)
            
            # Find all matches
            matches = regex.findall(log_content)
            
            # For patterns that return tuples (like grouped expressions)
            if matches and isinstance(matches[0], tuple):
                matches = [m[0] for m in matches]
            
            # Remove duplicates but maintain order
            unique_patterns = []
            seen = set()
            for match in matches:
                if match not in seen:
                    seen.add(match)
                    unique_patterns.append(match)
            
            return {'patterns': unique_patterns}
        
        except Exception as e:
            return {'error': f"Failed to find patterns: {str(e)}"}
    
    def visualize_log(self, log_content, visualization_type, time_frame='all'):
        """
        Generate visualization data from log content
        
        Args:
            log_content (str): The log content to visualize
            visualization_type (str): Type of visualization (timeseries, severity, source, heatmap)
            time_frame (str): Time frame to consider (all, hour, day, week, month)
            
        Returns:
            dict: Visualization data
        """
        try:
            # Parse the log content first
            parsed_data = self.parse_log(log_content)
            
            if 'error' in parsed_data:
                return parsed_data
            
            entries = parsed_data['entries']
            
            if not entries:
                return {'error': 'No valid log entries found'}
            
            # Filter entries by time frame if needed
            if time_frame != 'all':
                entries = self._filter_by_timeframe(entries, time_frame)
                
                if not entries:
                    return {'error': f'No entries found in the specified time frame ({time_frame})'}
            
            # Generate the specified visualization
            if visualization_type == 'timeseries':
                return self._generate_timeseries(entries)
            elif visualization_type == 'severity':
                return self._generate_severity_distribution(entries)
            elif visualization_type == 'source':
                return self._generate_source_distribution(entries)
            elif visualization_type == 'heatmap':
                return self._generate_heatmap(entries)
            else:
                return {'error': 'Invalid visualization type'}
        
        except Exception as e:
            return {'error': f"Failed to generate visualization: {str(e)}"}
    
    def monitor_log(self, log_file_path, format_type='auto', alert_keywords=None):
        """
        Monitor a log file for new entries
        
        Args:
            log_file_path (str): Path to the log file
            format_type (str): The log format type
            alert_keywords (list): List of keywords to trigger alerts
            
        Returns:
            dict: New log entries
        """
        try:
            # Check if the file exists
            if not os.path.exists(log_file_path):
                return {'error': f"Log file not found: {log_file_path}"}
            
            # Read the last few lines of the file
            # In a real app, we'd track file position between calls
            last_lines = self._read_last_lines(log_file_path, 10)
            
            if not last_lines:
                return {'entries': []}
            
            # Parse the lines
            entries = []
            for line in last_lines:
                try:
                    entry = self._parse_line(line, format_type)
                    if entry:
                        entries.append(entry)
                except Exception:
                    continue
            
            return {'entries': entries}
        
        except Exception as e:
            return {'error': f"Failed to monitor log: {str(e)}"}
    
    def _detect_format(self, log_content):
        """Detect the log format from content"""
        # Sample the first few lines
        lines = log_content.strip().split('\n')
        sample = '\n'.join(lines[:10])
        
        # Try to detect JSON format
        if sample.strip().startswith('{') and sample.strip().endswith('}'):
            try:
                json.loads(sample.strip())
                return 'json'
            except:
                pass
        
        # Try to match against known patterns
        for format_type, pattern in self.log_patterns.items():
            if format_type != 'json' and pattern and self._is_matching_format(sample, pattern):
                return format_type
        
        # Default to a generic format if not detected
        return 'syslog'
    
    def _is_matching_format(self, sample, pattern):
        """Check if the sample matches the given pattern"""
        try:
            grok_parser = Grok(pattern)  # Create Grok instance with the specific pattern
            matches = 0
            lines = sample.strip().split('\n')
            
            for line in lines:
                if grok_parser.match(line):
                    matches += 1
            
            # If more than 50% of lines match, it's probably the right format
            return matches > len(lines) / 2
        except Exception as e:
            print(f"Grok matching error: {e}")
            return False
    
    def _parse_line(self, line, format_type, custom_format=None):
        """Parse a single log line according to the specified format"""
        if not line.strip():
            return None
        
        # Parse JSON logs
        if format_type == 'json':
            try:
                data = json.loads(line)
                return {
                    'timestamp': data.get('timestamp', data.get('time', data.get('@timestamp'))),
                    'level': data.get('level', data.get('severity', data.get('log_level'))),
                    'message': data.get('message', data.get('msg', str(data))),
                    'source': data.get('source', data.get('logger', data.get('host'))),
                    'raw': line
                }
            except:
                # If JSON parsing fails, try other formats
                pass
        
        # Use custom format if provided
        pattern = custom_format if format_type == 'custom' else self.log_patterns.get(format_type)
        
        if pattern:
            try:
                grok_parser = Grok(pattern)  # Create Grok instance with the specific pattern
                match = grok_parser.match(line)
                
                if match:
                    return {
                        'timestamp': match.get('timestamp'),
                        'level': match.get('level', match.get('severity')),
                        'message': match.get('message'),
                        'source': match.get('source', match.get('program')),
                        'raw': line
                    }
            except Exception as e:
                print(f"Line parsing error with grok: {e}")
                pass        
        # Basic fallback parsing
        parts = line.split()
        entry = {'raw': line}
        
        # Try to extract timestamp
        for part in parts[:3]:  # Usually timestamp is at the beginning
            try:
                timestamp = parser.parse(part)
                entry['timestamp'] = timestamp.isoformat()
                break
            except:
                continue
        
        # Try to identify log level
        for part in parts:
            if part.lower() in ['error', 'warning', 'info', 'debug', 'critical', 'warn', 'err']:
                entry['level'] = part
                break
        
        # Set message as the rest of the line
        entry['message'] = line
        
        return entry
    
    def _filter_entries(self, entries, filter_expr):
        """Filter log entries based on expression"""
        if not filter_expr:
            return entries
        
        filtered = []
        for entry in entries:
            entry_text = json.dumps(entry).lower()
            
            # Simple filtering logic - could be extended for more complex expressions
            if ' OR ' in filter_expr:
                terms = [term.strip().lower() for term in filter_expr.split(' OR ')]
                if any(term in entry_text for term in terms):
                    filtered.append(entry)
            elif ' AND ' in filter_expr:
                terms = [term.strip().lower() for term in filter_expr.split(' AND ')]
                if all(term in entry_text for term in terms):
                    filtered.append(entry)
            else:
                if filter_expr.strip().lower() in entry_text:
                    filtered.append(entry)
        
        return filtered
    
    def _generate_statistics(self, entries):
        """Generate statistics from parsed log entries"""
        stats = {
            'total_entries': len(entries),
            'error_count': 0,
            'warning_count': 0,
            'info_count': 0
        }
        
        sources = Counter()
        timestamps = []
        time_distribution = defaultdict(lambda: {'error': 0, 'warning': 0, 'info': 0})
        
        for entry in entries:
            # Count by severity
            level = entry.get('level', '').lower()
            if 'error' in level or 'critical' in level or 'emergency' in level:
                stats['error_count'] += 1
                severity = 'error'
            elif 'warn' in level:
                stats['warning_count'] += 1
                severity = 'warning'
            else:
                stats['info_count'] += 1
                severity = 'info'
            
            # Count by source
            source = entry.get('source', 'unknown')
            if source:
                sources[source] += 1
            
            # Process timestamp if available
            if entry.get('timestamp'):
                try:
                    timestamp = parser.parse(entry['timestamp'])
                    timestamps.append(timestamp)
                    
                    # Aggregate by hour for time distribution
                    time_key = timestamp.strftime('%Y-%m-%d %H:00')
                    time_distribution[time_key][severity] += 1
                except:
                    pass
        
        # Get top sources
        top_sources = dict(sources.most_common(10))
        stats['top_sources'] = top_sources
        
        # Calculate time range
        if timestamps:
            stats['time_range'] = {
                'first': min(timestamps).isoformat(),
                'last': max(timestamps).isoformat(),
                'duration': str(max(timestamps) - min(timestamps))
            }
        
        # Sort time distribution by timestamp
        sorted_distribution = {}
        for time_key in sorted(time_distribution.keys()):
            sorted_distribution[time_key] = time_distribution[time_key]
        
        stats['time_distribution'] = sorted_distribution
        
        return stats
    
    def _identify_patterns(self, entries):
        """Identify common patterns in log entries"""
        # Extract all messages
        messages = [entry.get('message', '') for entry in entries if entry.get('message')]
        
                # Skip if no messages
        if not messages:
            return []
        
        # Group similar messages using basic text similarity
        patterns = []
        message_groups = defaultdict(list)
        
        for message in messages:
            # Create a simplified pattern by replacing numbers and specific identifiers
            simplified = re.sub(r'\b\d+\b', 'NUM', message)
            simplified = re.sub(r'\b[a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12}\b', 'UUID', simplified)
            simplified = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP_ADDR', simplified)
            
            message_groups[simplified].append(message)
        
        # Get the most common patterns
        common_patterns = Counter(message_groups.keys()).most_common(10)
        
        for pattern, count in common_patterns:
            example = message_groups[pattern][0]
            
            # Determine severity based on content
            severity = 'info'
            if re.search(r'(?i)\b(error|exception|fail|failed|failure)\b', pattern):
                severity = 'error'
            elif re.search(r'(?i)\b(warning|warn|caution)\b', pattern):
                severity = 'warning'
            
            patterns.append({
                'pattern': pattern,
                'occurrences': count,
                'example': example,
                'severity': severity
            })
        
        return patterns
    
    def _filter_by_timeframe(self, entries, time_frame):
        """Filter entries by the specified time frame"""
        now = datetime.datetime.now()
        cutoff = None
        
        if time_frame == 'hour':
            cutoff = now - datetime.timedelta(hours=1)
        elif time_frame == 'day':
            cutoff = now - datetime.timedelta(days=1)
        elif time_frame == 'week':
            cutoff = now - datetime.timedelta(weeks=1)
        elif time_frame == 'month':
            cutoff = now - datetime.timedelta(days=30)
        else:
            return entries  # No filtering needed
        
        filtered = []
        for entry in entries:
            if not entry.get('timestamp'):
                continue
            
            try:
                timestamp = parser.parse(entry['timestamp'])
                if timestamp >= cutoff:
                    filtered.append(entry)
            except:
                continue
        
        return filtered
    
    def _generate_timeseries(self, entries):
        """Generate time series visualization data"""
        # Group entries by timestamp and severity
        time_data = defaultdict(lambda: {'error': 0, 'warning': 0, 'info': 0})
        
        for entry in entries:
            if not entry.get('timestamp'):
                continue
            
            try:
                timestamp = parser.parse(entry['timestamp'])
                time_key = timestamp.strftime('%Y-%m-%d %H:%M')
                
                level = entry.get('level', '').lower()
                if 'error' in level or 'critical' in level:
                    time_data[time_key]['error'] += 1
                elif 'warn' in level:
                    time_data[time_key]['warning'] += 1
                else:
                    time_data[time_key]['info'] += 1
            except:
                continue
        
        # Sort by timestamp
        sorted_times = sorted(time_data.keys())
        
        # Prepare datasets for Chart.js
        datasets = [
            {
                'label': 'Errors',
                'data': [time_data[time_key]['error'] for time_key in sorted_times],
                'backgroundColor': 'rgba(220, 53, 69, 0.2)',
                'borderColor': 'rgba(220, 53, 69, 1)',
                'borderWidth': 1
            },
            {
                'label': 'Warnings',
                'data': [time_data[time_key]['warning'] for time_key in sorted_times],
                'backgroundColor': 'rgba(255, 193, 7, 0.2)',
                'borderColor': 'rgba(255, 193, 7, 1)',
                'borderWidth': 1
            },
            {
                'label': 'Info',
                'data': [time_data[time_key]['info'] for time_key in sorted_times],
                'backgroundColor': 'rgba(23, 162, 184, 0.2)',
                'borderColor': 'rgba(23, 162, 184, 1)',
                'borderWidth': 1
            }
        ]
        
        return {'visualization': {'labels': sorted_times, 'datasets': datasets}}
    
    def _generate_severity_distribution(self, entries):
        """Generate severity distribution visualization data"""
        severity_counts = {'Error': 0, 'Warning': 0, 'Info': 0, 'Other': 0}
        
        for entry in entries:
            level = entry.get('level', '').lower()
            if 'error' in level or 'critical' in level or 'emergency' in level:
                severity_counts['Error'] += 1
            elif 'warn' in level:
                severity_counts['Warning'] += 1
            elif 'info' in level or 'notice' in level:
                severity_counts['Info'] += 1
            else:
                severity_counts['Other'] += 1
        
        # Remove categories with zero count
        severity_counts = {k: v for k, v in severity_counts.items() if v > 0}
        
        # Prepare data for Chart.js
        labels = list(severity_counts.keys())
        data = list(severity_counts.values())
        colors = [
            'rgba(220, 53, 69, 0.8)',  # Error - red
            'rgba(255, 193, 7, 0.8)',  # Warning - yellow
            'rgba(23, 162, 184, 0.8)',  # Info - blue
            'rgba(108, 117, 125, 0.8)'  # Other - gray
        ]
        
        return {'visualization': {'labels': labels, 'data': data, 'colors': colors}}
    
    def _generate_source_distribution(self, entries):
        """Generate source distribution visualization data"""
        source_counts = Counter()
        
        for entry in entries:
            source = entry.get('source', 'unknown')
            if source:
                source_counts[source] += 1
        
        # Get the top sources
        top_sources = source_counts.most_common(10)
        
        # Prepare data for Chart.js
        labels = [source for source, _ in top_sources]
        data = [count for _, count in top_sources]
        
        return {'visualization': {'labels': labels, 'data': data}}
    
    def _generate_heatmap(self, entries):
        """Generate temporal heatmap visualization data"""
        # Initialize a 2D matrix for day of week (0-6) and hour of day (0-23)
        heatmap = np.zeros((7, 24), dtype=int)
        
        for entry in entries:
            if not entry.get('timestamp'):
                continue
            
            try:
                timestamp = parser.parse(entry['timestamp'])
                day_of_week = timestamp.weekday()  # 0 = Monday, 6 = Sunday
                hour_of_day = timestamp.hour
                
                # Sunday as 0 for consistency with frontend
                day_index = 6 if day_of_week == 6 else day_of_week
                
                heatmap[day_index, hour_of_day] += 1
            except:
                continue
        
        # Convert to the format expected by Chart.js
        heatmap_data = []
        max_value = np.max(heatmap)
        
        for day in range(7):
            for hour in range(24):
                if heatmap[day, hour] > 0:
                    heatmap_data.append({
                        'x': hour,
                        'y': day,
                        'v': int(heatmap[day, hour])
                    })
        
        return {'visualization': {'heatmap_data': heatmap_data, 'max_value': int(max_value)}}
    
    def _read_last_lines(self, file_path, num_lines=10):
        """Read the last n lines from a file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
                return lines[-num_lines:] if len(lines) > num_lines else lines
        except Exception as e:
            print(f"Error reading file: {str(e)}")
            return []

