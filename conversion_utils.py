import json
import csv
import xml.dom.minidom
import xml.etree.ElementTree as ET
import html
import base64
import yaml
import re
import io
import urllib.parse
from collections import OrderedDict

class ConversionTools:
    """Utilities for various data format conversions"""
    
    @staticmethod
    def detect_format(content):
        """Auto-detect the format of the given content"""
        content = content.strip()
        
        # Check if it's JSON
        try:
            json.loads(content)
            return "json"
        except:
            pass
        
        # Check if it's XML
        try:
            ET.fromstring(content)
            return "xml"
        except:
            pass
        
        # Check if it's YAML
        try:
            yaml.safe_load(content)
            if ":" in content and ("-" in content or "{" in content or "}" in content):
                return "yaml"
        except:
            pass
        
        # Check if it's CSV
        lines = content.split("\n")
        if len(lines) > 1:
            first_line = lines[0]
            if "," in first_line and len(first_line.split(",")) > 1:
                # Check if all lines have the same number of commas
                comma_counts = [line.count(",") for line in lines if line.strip()]
                if len(set(comma_counts)) == 1:  # All lines have the same number of commas
                    return "csv"
        
        # Default to text
        return "text"
    
    @staticmethod
    def convert_format(content, source_format, target_format, pretty_print=True, preserve_order=False):
        """Convert content from one format to another"""
        if source_format == target_format:
            return content
        
        # Parse the source content
        parsed_data = ConversionTools._parse_content(content, source_format, preserve_order)
        if parsed_data is None:
            raise ValueError(f"Failed to parse content as {source_format}")
        
        # Convert to the target format
        result = ConversionTools._convert_to_format(parsed_data, target_format, pretty_print)
        if result is None:
            raise ValueError(f"Failed to convert to {target_format}")
            
        return result
    
    @staticmethod
    def _parse_content(content, format_type, preserve_order=False):
        """Parse content based on its format type"""
        content = content.strip()
        
        if format_type == "json":
            try:
                if preserve_order:
                    return json.loads(content, object_pairs_hook=OrderedDict)
                return json.loads(content)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON: {str(e)}")
                
        elif format_type == "xml":
            try:
                root = ET.fromstring(content)
                return ConversionTools._xml_to_dict(root)
            except ET.ParseError as e:
                raise ValueError(f"Invalid XML: {str(e)}")
                
        elif format_type == "yaml":
            try:
                if preserve_order:
                    return yaml.safe_load(content)
                return yaml.safe_load(content)
            except yaml.YAMLError as e:
                raise ValueError(f"Invalid YAML: {str(e)}")
                
        elif format_type == "csv":
            try:
                csvreader = csv.reader(io.StringIO(content))
                rows = list(csvreader)
                if not rows:
                    return []
                    
                headers = rows[0]
                result = []
                
                for row in rows[1:]:
                    if len(row) == len(headers):
                        item = {}
                        for i, header in enumerate(headers):
                            item[header] = row[i]
                        result.append(item)
                
                return result
            except Exception as e:
                raise ValueError(f"CSV parsing error: {str(e)}")
                
        elif format_type == "text":
            return content
        
        return None
    
    @staticmethod
    def _convert_to_format(data, target_format, pretty_print=True):
        """Convert parsed data to the target format"""
        if target_format == "json":
            if pretty_print:
                return json.dumps(data, indent=2)
            return json.dumps(data)
            
        elif target_format == "xml":
            if isinstance(data, (dict, list)):
                root = ConversionTools._dict_to_xml("root", data)
                xml_str = ET.tostring(root, encoding='unicode')
                if pretty_print:
                    dom = xml.dom.minidom.parseString(xml_str)
                    return dom.toprettyxml(indent="  ")
                return xml_str
            return f"<root>{data}</root>"
            
        elif target_format == "yaml":
            if isinstance(data, (dict, list)):
                return yaml.dump(data, default_flow_style=False)
            return str(data)
            
        elif target_format == "csv":
            if isinstance(data, list) and all(isinstance(item, dict) for item in data):
                output = io.StringIO()
                if data:
                    fieldnames = list(data[0].keys())
                    writer = csv.DictWriter(output, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(data)
                    return output.getvalue()
            return ""
            
        elif target_format == "text":
            return str(data)
            
        return None
    
    @staticmethod
    def _xml_to_dict(element):
        """Convert XML element to dictionary"""
        result = {}
        
        # Add attributes
        for key, value in element.attrib.items():
            result[f"@{key}"] = value
            
        # Add children
        for child in element:
            child_data = ConversionTools._xml_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
                
        # Add text content
        text = element.text.strip() if element.text else ""
        if text:
            if result:
                result["#text"] = text
            else:
                return text
                
        return result
    
    @staticmethod
    def _dict_to_xml(tag, data):
        """Convert dictionary to XML element"""
        element = ET.Element(tag)
        
        if isinstance(data, dict):
            for key, value in data.items():
                if key.startswith('@'):
                    element.set(key[1:], str(value))
                elif key == "#text":
                    element.text = str(value)
                else:
                    child = ConversionTools._dict_to_xml(key, value)
                    element.append(child)
        elif isinstance(data, list):
            for item in data:
                child = ConversionTools._dict_to_xml(tag.rstrip('s'), item)
                element.append(child)
        else:
            element.text = str(data)
            
        return element
    
    @staticmethod
    def csv_to_json(csv_content, delimiter=',', has_header=True, trim_whitespace=True, type_detection=True):
        """Convert CSV to JSON"""
        try:
            reader = csv.reader(io.StringIO(csv_content), delimiter=delimiter)
            rows = list(reader)
            
            if not rows:
                return "[]"
                
            if has_header:
                headers = rows[0]
                data_rows = rows[1:]
            else:
                # Generate column names
                headers = [f"col{i}" for i in range(len(rows[0]))]
                data_rows = rows
                
            if trim_whitespace:
                headers = [h.strip() for h in headers]
                
            result = []
            
            for row in data_rows:
                if len(row) != len(headers):
                    # Skip malformed rows
                    continue
                    
                item = {}
                for i, value in enumerate(row):
                    if i >= len(headers):
                        break
                        
                    if trim_whitespace:
                        value = value.strip()
                        
                    if type_detection:
                        # Try to convert to appropriate type
                        if value.lower() == 'true':
                            value = True
                        elif value.lower() == 'false':
                            value = False
                        elif value.lower() == 'null' or value == '':
                            value = None
                        else:
                            try:
                                if '.' in value:
                                    value = float(value)
                                else:
                                    value = int(value)
                            except:
                                pass
                    
                    item[headers[i]] = value
                
                result.append(item)
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            raise ValueError(f"CSV to JSON conversion error: {str(e)}")
    
    @staticmethod
    def transpose_csv(csv_content, delimiter=','):
        """Transpose a CSV (swap rows and columns)"""
        try:
            reader = csv.reader(io.StringIO(csv_content), delimiter=delimiter)
            rows = list(reader)
            
            if not rows:
                return ""
                
            # Find the maximum row length to handle ragged CSVs
            max_row_length = max(len(row) for row in rows)
            
            # Pad rows if necessary
            padded_rows = [row + [''] * (max_row_length - len(row)) for row in rows]
            
            # Transpose the rows
            transposed = list(zip(*padded_rows))
            
            # Convert to CSV
            output = io.StringIO()
            writer = csv.writer(output, delimiter=delimiter)
            writer.writerows(transposed)
            
            return output.getvalue()
            
        except Exception as e:
            raise ValueError(f"CSV transpose error: {str(e)}")
    
    @staticmethod
    def manipulate_csv(csv_content, manipulation_type, **kwargs):
        """Manipulate CSV data in various ways"""
        try:
            # Parse CSV
            reader = csv.reader(io.StringIO(csv_content), delimiter=kwargs.get('delimiter', ','))
            rows = list(reader)
            
            if not rows:
                return ""
                
            headers = rows[0]
            data_rows = rows[1:]
            
            # Apply manipulation
            if manipulation_type == 'sort':
                column = kwargs.get('column', '')
                col_index = -1
                
                # Determine column index
                try:
                    col_index = int(column)
                except:
                    if column in headers:
                        col_index = headers.index(column)
                
                if col_index >= 0 and col_index < len(headers):
                    reverse = kwargs.get('reverse', False)
                    numeric = kwargs.get('numeric', False)
                    
                    # Sort data rows
                    if numeric:
                        # Convert to numeric if possible
                        def get_numeric(val):
                            try:
                                return float(val)
                            except:
                                return 0
                        
                        data_rows.sort(key=lambda row: get_numeric(row[col_index]) if col_index < len(row) else "", reverse=reverse)
                    else:
                        data_rows.sort(key=lambda row: row[col_index] if col_index < len(row) else "", reverse=reverse)
            
            elif manipulation_type == 'filter':
                column = kwargs.get('column', '')
                condition = kwargs.get('condition', '')
                value = kwargs.get('value', '')
                col_index = -1
                
                # Determine column index
                try:
                    col_index = int(column)
                except:
                    if column in headers:
                        col_index = headers.index(column)
                
                if col_index >= 0 and col_index < len(headers):
                    filtered_rows = []
                    
                    for row in data_rows:
                        if col_index >= len(row):
                            continue
                            
                        cell_value = row[col_index]
                        
                        if condition == 'contains':
                            if value.lower() in cell_value.lower():
                                filtered_rows.append(row)
                        elif condition == 'equals':
                            if cell_value.lower() == value.lower():
                                filtered_rows.append(row)
                        elif condition == 'startsWith':
                            if cell_value.lower().startswith(value.lower()):
                                filtered_rows.append(row)
                        elif condition == 'endsWith':
                            if cell_value.lower().endswith(value.lower()):
                                filtered_rows.append(row)
                        elif condition == 'greaterThan':
                            try:
                                if float(cell_value) > float(value):
                                    filtered_rows.append(row)
                            except:
                                pass
                        elif condition == 'lessThan':
                            try:
                                if float(cell_value) < float(value):
                                    filtered_rows.append(row)
                            except:
                                pass
                    
                    data_rows = filtered_rows
            
            elif manipulation_type == 'extract':
                columns = kwargs.get('columns', '')
                
                if columns:
                    col_indices = []
                    
                    # Parse column indices
                    for col in columns.split(','):
                        col = col.strip()
                        try:
                            idx = int(col)
                            if 0 <= idx < len(headers):
                                col_indices.append(idx)
                        except:
                            if col in headers:
                                col_indices.append(headers.index(col))
                    
                    if col_indices:
                        # Extract specified columns
                        new_headers = [headers[i] for i in col_indices]
                        new_data_rows = []
                        
                        for row in data_rows:
                            new_row = []
                            for i in col_indices:
                                if i < len(row):
                                    new_row.append(row[i])
                                else:
                                    new_row.append("")
                            new_data_rows.append(new_row)
                        
                        headers = new_headers
                        data_rows = new_data_rows
            
            elif manipulation_type == 'addColumn':
                new_column_name = kwargs.get('new_column_name', 'New Column')
                formula = kwargs.get('formula', '')
                
                if formula:
                    # Add a new column with calculated values
                    headers.append(new_column_name)
                    
                    # Process each data row
                    for i, row in enumerate(data_rows):
                        # Create a context for formula evaluation
                        context = {}
                        for j, header in enumerate(headers[:-1]):  # Exclude the new column
                            col_key = f"col{j}"
                            if j < len(row):
                                try:
                                    # Try to convert to number
                                    context[col_key] = float(row[j])
                                except:
                                    context[col_key] = row[j]
                        
                        # Replace column references in formula
                        eval_formula = formula
                        for j in range(len(headers) - 1):
                            eval_formula = eval_formula.replace(f"col{j}", f"context['col{j}']")
                        
                        try:
                            # Evaluate the formula
                            result = eval(eval_formula)
                            row.append(str(result))
                        except Exception as e:
                            # If formula fails, add empty cell
                            row.append("")
            
            # Convert back to CSV
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(headers)
            writer.writerows(data_rows)
            
            return output.getvalue()
            
        except Exception as e:
            raise ValueError(f"CSV manipulation error: {str(e)}")
    
    @staticmethod
    def format_code(code, language, indent_with_tabs=False, indent_size=4, wrap_lines=True, minify=False):
        """Format code in various languages"""
        if minify:
            return ConversionTools._minify_code(code, language)
        
        try:
            # For JSON
            if language == 'json':
                parsed = json.loads(code)
                return json.dumps(parsed, indent=indent_size if not indent_with_tabs else '\t')
            
            # For JavaScript, HTML, CSS, XML, etc.
            # In a real implementation, you would use language-specific formatters
            # This is a simplified version that just does basic indentation for demonstration
            
            if language in ['javascript', 'html', 'css', 'xml', 'sql', 'python']:
                # Use an external library like jsbeautifier, cssbeautifier, etc.
                # Here we're just doing a simple indent/prettify
                lines = code.split('\n')
                indentation = 0
                result = []
                
                open_chars = {'(': ')', '{': '}', '[': ']'}
                close_chars = {')', '}', ']'}
                
                for line in lines:
                    stripped = line.strip()
                    
                    # Decrease indent for closing brackets
                    if stripped and stripped[0] in close_chars:
                        indentation = max(0, indentation - 1)
                    
                    # Add line with correct indentation
                    indent_char = '\t' if indent_with_tabs else ' ' * indent_size
                    result.append(indent_char * indentation + stripped)
                    
                    # Increase indent for opening brackets
                    if stripped:
                        last_char = stripped[-1]
                        if last_char in open_chars:
                            indentation += 1
                
                return '\n'.join(result)
            
            return code
            
        except Exception as e:
            raise ValueError(f"Code formatting error: {str(e)}")
    
    @staticmethod
    def _minify_code(code, language):
        """Minify code by removing whitespace and comments"""
        if language == 'json':
            try:
                parsed = json.loads(code)
                return json.dumps(parsed, separators=(',', ':'))
            except:
                pass
        
        # Simple minification: remove comments and excess whitespace
        # For proper minification, use language-specific tools
        result = code
        
        # Remove comments (simplified)
        if language in ['javascript', 'css']:
            # Remove single-line comments
            result = re.sub(r'//.*?\n', '\n', result)
            # Remove multi-line comments
            result = re.sub(r'/\*.*?\*/', '', result, flags=re.DOTALL)
        
        # Remove excess whitespace
        result = re.sub(r'\s+', ' ', result)
        result = re.sub(r';\s+', ';', result)
        result = re.sub(r'{\s+', '{', result)
        result = re.sub(r'}\s+', '}', result)
        result = re.sub(r',\s+', ',', result)
        result = re.sub(r':\s+', ':', result)
        result = re.sub(r'>\s+<', '><', result)
        
        return result.strip()
    
    @staticmethod
    def encode_url(text):
        """URL encode text"""
        try:
            return urllib.parse.quote(text)
        except Exception as e:
            raise ValueError(f"URL encoding error: {str(e)}")
    
    @staticmethod
    def decode_url(text):
        """URL decode text"""
        try:
            return urllib.parse.unquote(text)
        except Exception as e:
            raise ValueError(f"URL decoding error: {str(e)}")
    
    @staticmethod
    def encode_base64(text):
        """Base64 encode text"""
        try:
            return base64.b64encode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Base64 encoding error: {str(e)}")
    
    @staticmethod
    def decode_base64(text):
        """Base64 decode text"""
        try:
            return base64.b64decode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Base64 decoding error: {str(e)}")
    
    @staticmethod
    def encode_file_base64(file_data):
        """Base64 encode binary file data"""
        try:
            return base64.b64encode(bytes(file_data)).decode('utf-8')
        except Exception as e:
            raise ValueError(f"File encoding error: {str(e)}")
    
    @staticmethod
    def decode_file_base64(base64_data):
        """Base64 decode to binary file data"""
        try:
            return base64.b64decode(base64_data.encode('utf-8'))
        except Exception as e:
            raise ValueError(f"File decoding error: {str(e)}")
    
    @staticmethod
    def encode_html(text):
        """Encode text to HTML entities"""
        try:
            return html.escape(text)
        except Exception as e:
            raise ValueError(f"HTML encoding error: {str(e)}")
    
    @staticmethod
    def decode_html(text):
        """Decode HTML entities to text"""
        try:
            return html.unescape(text)
        except Exception as e:
            raise ValueError(f"HTML decoding error: {str(e)}")

