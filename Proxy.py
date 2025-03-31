# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
import time  # For handling cache control headers timestamps

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  serverSocket.bind((proxyHost, proxyPort))
  # ~~~~ END CODE INSERT ~~~~
  print ('Port is bound')
except:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  serverSocket.listen(1)
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# Step 8: Helper function for parsing response headers
def parse_headers(response):
    # Find the separator between headers and body
    header_end = response.find(b'\r\n\r\n')
    if header_end == -1:
        return {}, response
    
    headers_raw = response[:header_end].decode('latin-1', errors='replace')
    body = response[header_end + 4:]  # Skip \r\n\r\n
    
    # Parse headers
    headers = {}
    lines = headers_raw.split('\r\n')
    status_line = lines[0]
    headers['status'] = status_line
    
    # Get status code
    try:
        status_code = int(status_line.split()[1])
        headers['status_code'] = status_code
    except (IndexError, ValueError):
        headers['status_code'] = 0
    
    # Parse other headers
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()
    
    return headers, body

# Step 8: Check cache control headers and if response should be cached
def should_cache_response(headers):
    # Check status code
    status_code = headers.get('status_code', 0)
    
    # According to HTTP specification:
    # 200 OK - Cacheable
    # 301 Moved Permanently - Cacheable
    # 302 Found - Not cacheable unless explicitly indicated
    # 304 Not Modified - Cacheable
    # 404 Not Found - Not cacheable unless explicitly indicated
    
    # Get Cache-Control header
    cache_control = headers.get('cache-control', '')
    
    # Check for explicit no-cache directives
    if 'no-store' in cache_control or 'no-cache' in cache_control:
        print(f"Response has no-store or no-cache directive, not caching")
        return False
    
    # Check max-age directive
    max_age = None
    if 'max-age=' in cache_control:
        max_age_part = cache_control.split('max-age=')[1]
        try:
            max_age = int(max_age_part.split(',')[0].strip())
            print(f"Found max-age directive: {max_age} seconds")
            if max_age == 0:
                print("Response has max-age=0, not caching")
                return False
        except (ValueError, IndexError):
            pass
    
    # Handle various status codes
    if status_code == 200:
        # 200 OK - Cacheable by default
        return True
    elif status_code == 301:
        # 301 Moved Permanently - Cacheable by default
        print("301 response cached by default")
        return True
    elif status_code == 304:
        # 304 Not Modified - Cacheable by default, but need to update existing cache
        print("304 Not Modified response - updating cache")
        return True
    elif status_code in [302, 307, 404]:
        # These status codes are not cached unless explicitly indicated
        if 'public' in cache_control or 'private' in cache_control or max_age is not None:
            print(f"{status_code} response cached due to explicit cache directive")
            return True
        else:
            print(f"{status_code} response not cached (no explicit caching directive)")
            return False
    
    # Other status codes are not cached by default
    print(f"Status code {status_code} not cached by default")
    return False

# Step 8: Enhanced cache saving function with timestamp
def save_to_cache(response, cache_location):
    try:
        # Parse headers and body
        headers, body = parse_headers(response)
        
        if should_cache_response(headers):
            # Create cache directory if it doesn't exist
            cache_dir = os.path.dirname(cache_location)
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir)
            
            # Add cache timestamp header
            timestamp = int(time.time())
            header_addition = f"X-Cached-Timestamp: {timestamp}\r\n"
            
            # Find header end position
            header_end = response.find(b'\r\n\r\n')
            if header_end != -1:
                # Insert timestamp between headers and body
                new_response = response[:header_end] + header_addition.encode('latin-1') + response[header_end:]
                
                # Save to cache file
                with open(cache_location, 'wb') as cache_file:
                    cache_file.write(new_response)
                print(f"Response cached with timestamp: {timestamp}")
                return True
            else:
                # Cannot parse headers
                with open(cache_location, 'wb') as cache_file:
                    cache_file.write(response)
                print("Response cached without modification (could not parse headers)")
                return True
        return False
    except Exception as e:
        print(f"Error saving to cache: {str(e)}")
        return False

# Step 8: Check if cache is expired
def is_cache_valid(cache_location):
    try:
        with open(cache_location, 'r') as cache_file:
            content = cache_file.read()
            
            # Look for timestamp header
            timestamp_match = re.search(r'X-Cached-Timestamp:\s*(\d+)', content)
            if timestamp_match:
                timestamp = int(timestamp_match.group(1))
                current_time = int(time.time())
                age = current_time - timestamp
                
                # Look for max-age directive
                max_age_match = re.search(r'Cache-Control:.*?max-age=(\d+)', content, re.IGNORECASE)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if age > max_age:
                        print(f"Cache expired: Age {age}s > max-age {max_age}s")
                        return False
                    else:
                        print(f"Cache valid: Age {age}s <= max-age {max_age}s")
                        return True
            
            # If no timestamp or max-age found, default to valid cache
            return True
    except Exception as e:
        print(f"Error checking cache validity: {str(e)}")
        return False

# Step 9: Add Via header
def add_via_header(response):
    try:
        # Find header end position
        header_end = response.find(b'\r\n\r\n')
        if header_end != -1:
            headers = response[:header_end].decode('latin-1', errors='replace')
            body = response[header_end + 4:]
            
            # Check if Via header already exists
            if 'via:' not in headers.lower():
                # Add Via header
                via_header = f"Via: 1.1 {proxyHost}:{proxyPort} (Python-Proxy)\r\n"
                new_response = response[:header_end] + via_header.encode('latin-1') + b'\r\n\r\n' + body
                return new_response
        
        # If cannot parse or Via header already exists, return original response
        return response
    except Exception as e:
        print(f"Error adding Via header: {str(e)}")
        return response

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, addr = serverSocket.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection from:', addr)
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)
    
    # Step 8: Check if cache exists and is valid
    if fileExists and is_cache_valid(cacheLocation):
        # Return response from cache
        print ('Cache hit! Loading from cache file: ' + cacheLocation)
        
        # Check if it's a binary file (like an image)
        try:
            # Try to open in text mode
            cacheFile = open(cacheLocation, "r")
            cacheData = cacheFile.readlines()
            
            # Add Via header
            output = []
            header_end_found = False
            for line in cacheData:
                if line.strip() == "" and not header_end_found:
                    # Add Via header before empty line (if not already present)
                    if not any(line.lower().startswith('via:') for line in output):
                        output.append(f"Via: 1.1 {proxyHost}:{proxyPort} (Python-Proxy)\r\n")
                    header_end_found = True
                output.append(line)
            
            # Send response to client
            for line in output:
                clientSocket.send(line.encode())
            
            cacheFile.close()
            print ('Sent to the client from cache (text mode)')
        except UnicodeDecodeError:
            # Likely a binary file, reopen in binary mode
            with open(cacheLocation, "rb") as binary_file:
                data = binary_file.read()
                # Add Via header
                data_with_via = add_via_header(data)
                clientSocket.sendall(data_with_via)
                print ('Sent to the client from cache (binary mode)')
    else:
        # Cache miss or expired
        if fileExists:
            print("Cache expired or invalid, refetching from origin server")
        else:
            print("Cache miss, fetching from origin server")
        raise FileNotFoundError("Force cache miss")
            
  except Exception as e:
    # Cache miss - Step 7: Get resource from origin server
    print(f'Cache miss or invalid! Fetching from origin server... ({str(e)})')
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerSocket.connect((address, 80))
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      originServerRequest = f'GET {resource} HTTP/1.1'
      originServerRequestHeader = f'Host: {hostname}\r\nConnection: close'
      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      response = b''
      while True:
          data = originServerSocket.recv(BUFFER_SIZE)
          if not data:
              break
          response += data      
      # ~~~~ END CODE INSERT ~~~~

      # Parse response headers and status code
      headers, body = parse_headers(response)
      status_code = headers.get('status_code', 0)
      print(f"Received response from origin server: {headers.get('status', 'Unknown Status')}")
      
      # Step 8: Handle redirects
      if status_code in [301, 302, 303, 307, 308]:
          print(f"Received redirect response (status {status_code})")
          # Add Via header
          response_with_via = add_via_header(response)
          
          # Send to client
          clientSocket.sendall(response_with_via)
          
          # Check if should be cached
          if should_cache_response(headers):
              print(f"Caching redirect response (status {status_code})")
              save_to_cache(response_with_via, cacheLocation)
          else:
              print(f"Not caching redirect response (status {status_code})")
      else:
          # Non-redirect response
          # Add Via header
          response_with_via = add_via_header(response)
          
          # Send to client
          clientSocket.sendall(response_with_via)
          
          # Check if should be cached
          if should_cache_response(headers):
              print("Caching response")
              save_to_cache(response_with_via, cacheLocation)
          else:
              print("Not caching response")

      # Finished communicating with origin server - shutdown socket writes
      print ('Origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('Client socket shutdown for writing')
    except OSError as err:
      print ('Origin server request failed. ' + str(err))
      # Send error message to client
      errorMsg = "HTTP/1.1 502 Bad Gateway\r\n"
      errorMsg += "Content-Type: text/html\r\n"
      errorMsg += "Via: 1.1 " + proxyHost + ":" + str(proxyPort) + " (Python-Proxy)\r\n"
      errorMsg += "\r\n"
      errorMsg += "<html><body><h1>502 Bad Gateway</h1>"
      errorMsg += "<p>Error connecting to the origin server</p>"
      errorMsg += "<p>Error details: " + str(err) + "</p>"
      errorMsg += "</body></html>"
      clientSocket.send(errorMsg.encode())

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')

# Step 9 testing instructions:
# 1. Test the proxy server using telnet:
#    telnet proxy_host proxy_port
#    GET http://example.com/ HTTP/1.1
#    Host: example.com
#    (press Enter twice)
#
# 2. Test the proxy server using cURL:
#    curl -v -x proxy_host:proxy_port http://example.com/
#
# 3. Capture traffic using Wireshark:
#    - Filter: host example.com and tcp port 80
#    - Observe communication between proxy and origin server 