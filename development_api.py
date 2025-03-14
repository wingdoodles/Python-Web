from flask import Blueprint, jsonify, request, current_app
import re
import json
import uuid
import os
import time
import requests
from datetime import datetime
from pathlib import Path

# Create a blueprint for development tools
dev_bp = Blueprint('dev', __name__, url_prefix='/api/dev')

# In-memory storage for snippets and API tests (replace with database in production)
snippets_storage = {}
api_tests_storage = {}
regex_history = []

# Regex Tester
@dev_bp.route('/regex/test', methods=['POST'])
def regex_test():
    try:
        data = request.get_json()
        pattern = data.get('pattern', '')
        text = data.get('text', '')
        flags = data.get('flags', '')
        
        # Parse regex flags
        regex_flags = 0
        if 'i' in flags:
            regex_flags |= re.IGNORECASE
        if 'm' in flags:
            regex_flags |= re.MULTILINE
        if 's' in flags:
            regex_flags |= re.DOTALL
        
        # Perform regex match
        result = {
            'is_valid': True,
            'matches': [],
            'error': None
        }
        
        try:
            regex = re.compile(pattern, regex_flags)
            
            # Find all matches
            matches = []
            for match in regex.finditer(text):
                match_data = {
                    'start': match.start(),
                    'end': match.end(),
                    'value': match.group(),
                    'groups': []
                }
                
                # Add group information
                for i, group in enumerate(match.groups(default='')):
                    match_data['groups'].append({
                        'index': i + 1,
                        'value': group,
                        'name': match.lastgroup if match.lastgroup and i == len(match.groups()) - 1 else None
                    })
                
                matches.append(match_data)
            
            result['matches'] = matches
            
            # Store in history if not already present
            if pattern and pattern not in [item['pattern'] for item in regex_history]:
                regex_history.append({
                    'id': str(uuid.uuid4()),
                    'pattern': pattern,
                    'flags': flags,
                    'created_at': datetime.now().isoformat()
                })
                # Limit history to 20 items
                if len(regex_history) > 20:
                    regex_history.pop(0)
            
        except re.error as e:
            result['is_valid'] = False
            result['error'] = str(e)
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dev_bp.route('/regex/history', methods=['GET'])
def regex_history_endpoint():
    return jsonify({'history': regex_history})

@dev_bp.route('/regex/history/<id>', methods=['DELETE'])
def delete_regex_history(id):
    global regex_history
    regex_history = [item for item in regex_history if item['id'] != id]
    return jsonify({'success': True})

# API Tools
@dev_bp.route('/api/test', methods=['POST'])
def api_test():
    try:
        data = request.get_json()
        url = data.get('url', '')
        method = data.get('method', 'GET').upper()
        headers = data.get('headers', {})
        body = data.get('body', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Convert headers to dict if it's a string
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except:
                headers = {}
        
        # Convert body to dict if it's a string and content-type is application/json
        body_dict = None
        if isinstance(body, str) and body and headers.get('Content-Type', '').lower() == 'application/json':
            try:
                body_dict = json.loads(body)
            except:
                body_dict = None
        
        start_time = time.time()
        
        # Make request
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=10)
            elif method == 'POST':
                if body_dict is not None:
                    response = requests.post(url, json=body_dict, headers=headers, timeout=10)
                else:
                    response = requests.post(url, data=body, headers=headers, timeout=10)
            elif method == 'PUT':
                if body_dict is not None:
                    response = requests.put(url, json=body_dict, headers=headers, timeout=10)
                else:
                    response = requests.put(url, data=body, headers=headers, timeout=10)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=10)
            elif method == 'PATCH':
                if body_dict is not None:
                    response = requests.patch(url, json=body_dict, headers=headers, timeout=10)
                else:
                    response = requests.patch(url, data=body, headers=headers, timeout=10)
            elif method == 'HEAD':
                response = requests.head(url, headers=headers, timeout=10)
            elif method == 'OPTIONS':
                response = requests.options(url, headers=headers, timeout=10)
            else:
                return jsonify({'error': f'Unsupported method: {method}'}), 400
            
            # Calculate response time
            response_time = (time.time() - start_time) * 1000  # ms
            
            # Get response content type
            content_type = response.headers.get('Content-Type', '')
            
            # Format response body based on content type
            response_body = response.text
            is_json = False
            if 'application/json' in content_type:
                try:
                    response_body = response.json()
                    is_json = True
                except:
                    pass
            
            # Create response object
            result = {
                'status': response.status_code,
                'time': response_time,
                'headers': dict(response.headers),
                'body': response_body,
                'is_json': is_json,
                'url': response.url
            }
            
            # Save to history with a unique ID
            test_id = str(uuid.uuid4())
            api_tests_storage[test_id] = {
                'id': test_id,
                'url': url,
                'method': method,
                'headers': headers,
                'body': body,
                'response': {
                    'status': response.status_code,
                    'time': response_time,
                    'content_type': content_type
                },
                'timestamp': datetime.now().isoformat()
            }
            
            # Limit storage to 20 items
            if len(api_tests_storage) > 20:
                oldest_key = sorted(api_tests_storage.keys(), 
                                    key=lambda k: api_tests_storage[k]['timestamp'])[0]
                del api_tests_storage[oldest_key]
            
            return jsonify(result)
            
        except requests.exceptions.RequestException as e:
            return jsonify({
                'error': str(e),
                'type': type(e).__name__
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dev_bp.route('/api/history', methods=['GET'])
def api_test_history():
    # Return list of API tests, sorted by timestamp
    history = list(api_tests_storage.values())
    history.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify({'history': history})

@dev_bp.route('/api/history/<id>', methods=['GET'])
def api_test_detail(id):
    if id in api_tests_storage:
        return jsonify(api_tests_storage[id])
    return jsonify({'error': 'Test not found'}), 404

@dev_bp.route('/api/history/<id>', methods=['DELETE'])
def api_test_delete(id):
    if id in api_tests_storage:
        del api_tests_storage[id]
        return jsonify({'success': True})
    return jsonify({'error': 'Test not found'}), 404

# Code Snippets Management
@dev_bp.route('/snippets', methods=['GET'])
def list_snippets():
    snippets = list(snippets_storage.values())
    snippets.sort(key=lambda x: x['updated_at'], reverse=True)
    return jsonify({'snippets': snippets})

@dev_bp.route('/snippets', methods=['POST'])
def create_snippet():
    try:
        data = request.get_json()
        title = data.get('title', 'Untitled')
        code = data.get('code', '')
        language = data.get('language', 'text')
        description = data.get('description', '')
        tags = data.get('tags', [])
        
        snippet_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        
        snippet = {
            'id': snippet_id,
            'title': title,
            'code': code,
            'language': language,
            'description': description,
            'tags': tags,
            'created_at': now,
            'updated_at': now
        }
        
        snippets_storage[snippet_id] = snippet
        return jsonify(snippet), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dev_bp.route('/snippets/<id>', methods=['GET'])
def get_snippet(id):
    if id in snippets_storage:
        return jsonify(snippets_storage[id])
    return jsonify({'error': 'Snippet not found'}), 404

@dev_bp.route('/snippets/<id>', methods=['PUT'])
def update_snippet(id):
    if id not in snippets_storage:
        return jsonify({'error': 'Snippet not found'}), 404
    
    try:
        data = request.get_json()
        snippet = snippets_storage[id]
        
        # Update fields
        snippet['title'] = data.get('title', snippet['title'])
        snippet['code'] = data.get('code', snippet['code'])
        snippet['language'] = data.get('language', snippet['language'])
        snippet['description'] = data.get('description', snippet['description'])
        snippet['tags'] = data.get('tags', snippet['tags'])
        snippet['updated_at'] = datetime.now().isoformat()
        
        snippets_storage[id] = snippet
        return jsonify(snippet)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dev_bp.route('/snippets/<id>', methods=['DELETE'])
def delete_snippet(id):
    if id in snippets_storage:
        del snippets_storage[id]
        return jsonify({'success': True})
    return jsonify({'error': 'Snippet not found'}), 404

# Extension points for future development tools
@dev_bp.route('/tools/info', methods=['GET'])
def dev_tools_info():
    return jsonify({
        'regex_tester': {
            'available': True,
            'history_count': len(regex_history)
        },
        'api_tools': {
            'available': True,
            'tests_count': len(api_tests_storage)
        },
        'snippets': {
            'available': True,
            'count': len(snippets_storage)
        }
    })
