import json
import openai
import requests
from STR_Command import CommandData
from ENUM_Command import CommandEnum
from termcolor import colored
from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import pyodbc
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

app = Flask(__name__)
CORS(app)
API_URL='http://localhost:5167'
GPT_MODEL = "gpt-3.5-turbo-0613"
OPENAI_API_KEY = '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'
client = openai.OpenAI(api_key=OPENAI_API_KEY)
DB_SERVER = '192.168.0.200\\testinstance'
DB_DATABASE = 'SmartWMS'
DB_USERNAME = 'wms'
DB_PASSWORD = '1'

last_message_index = -1

@app.route('/get_message', methods=['GET'])
def get_message():
    global messages
    global last_message_index 
    new_messages = messages[last_message_index + 1:]
    contents = [
    {
        'role': message['role'] if isinstance(message, dict) else message.role,
        'message': message['content'] if isinstance(message, dict) and message.get('content', '') != '' else (message.content if hasattr(message, 'content') and message.content != '' else None)
    }
    for message in messages
    if isinstance(message, dict) or (hasattr(message, 'content') and message.content != '')
    ]
    last_message_index = len(messages) - 1  
    return jsonify({'messages': contents})


@app.route('/add_message', methods=['POST'])
def add_message():
    content = request.json.get('content')
    if content is not None:
        global messages
        messages.append({"role": "user", "content": content})
        send_to_model()
        return jsonify({'success': True, 'message': 'Message sent successfully'}), 201
    else:
        return jsonify({'success': False, 'message': 'No content provided'}), 400
    
@app.route('/do_login', methods=['POST'])
def do_login():
    login = request.json.get('login')
    password = request.json.get('password')
    if login is not None and password is not None:     
        if  validate_login(login,password):
            return jsonify({'success':  True,'message': 'User logged successfully'}), 201
        else:
            return jsonify({'success': False, 'message': 'Wrong login or password'}), 201
    else:
        return jsonify({'success': False, 'message': 'No login or password provided'}), 400
    
@app.route('/new_chat', methods=['POST'])
def new_chat():
    global messages
    messages = []
    messages.append({"role": "system", "content": "Don't make assumptions about what values to plug into functions. Ask for clarification if a user request is ambiguous."})
    return jsonify({'success': True, 'message': 'New chat initialized'}), 201
    
def validate_login(username, password):
    conn_str = f'DRIVER={{SQL Server}};SERVER={DB_SERVER};DATABASE={DB_DATABASE};UID={DB_USERNAME};PWD={DB_PASSWORD}'
    conn = pyodbc.connect(conn_str)
    
    cursor = conn.cursor()
    query = 'SELECT * FROM Kar_Operator'
    cursor.execute(query)
    rows = cursor.fetchall()

    for row in rows:
        if row.ID_Operator == username and row.Haslo == '1NFl0EK3a+KP0UoAA4D44Q==': #do testów - szyforwanie nie działa
            return True
    conn.close()

    return False
    
def decrypt_password(password):
    salt = b"9369888615820315512323246139138941212977"
    
    # Derive key and IV
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        iterations=10000,
        salt=salt,
        length=48,  # 32 bytes for key + 16 bytes for IV
        backend=default_backend()
    )
    key_iv = kdf.derive(password.encode())

    # Separate key and IV
    key = key_iv[:32]
    iv = key_iv[32:]

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of the block size (AES block size is 128 bits)
    plaintext = password.encode() + b"\0" * (128 - len(password.encode()) % 128)

    encrypted_password = encryptor.update(plaintext) + encryptor.finalize()

    result = base64.b64encode(encrypted_password).decode()

    expected_encrypted_password = "1NFl0EK3a+KP0UoAA4D44Q=="
    print(f"Encrypted Password: {result}")
    print(f"Expected Encrypted Password: {expected_encrypted_password}")

    return result


def post_blink_command(payload):
    endpoint = f"{API_URL}/blink-api/v2/commands"
    headers = {
        'Content-Type': 'application/json',
        'accept': 'text/plain'
              }
    response = requests.post(endpoint, json=payload, headers=headers)

    if response.status_code == 200:
        id = json.loads(response.text)["data"][0]["ID"]
        text = f"Sended to server. Number of request {id}."
        return text
    else:
        return f"Error while sending the request to the server. Error code: {response.status_code}"
    
def get_views(endpoint):
    endpoint = f"{API_URL}/blink-api/v2/views/{endpoint}"
    response = requests.get(endpoint)

    if response.status_code == 200:
        return json.dumps(response.text)
    else:
        return  f"Error while sending the request to the server. Error code: {response.status_code}"
        
def blink_station_move(tower, window, location):
    command = CommandData(
                command=CommandEnum.STATION_MOVE.value,
                parameter1=tower,
                parameter2=window,
                parameter3=location)
    
    return post_blink_command(command.to_json())

def blink_laod_table(article_index, batch, laser_number, laser_table_number, material_source, ignore_laser_table_material):
    command = CommandData(
        command=CommandEnum.LU_LOAD.value,
        parameter1=article_index,
        parameter2=batch,
        parameter3=laser_number,
        parameter4=laser_table_number,
        parameter5=material_source,
        parameter6=ignore_laser_table_material
    )

    return post_blink_command(command.to_json())

def blink_unload_table(article_index, batch, laser_number, laser_table_number, unloading_tray, ignore_laser_table_material, empty_tray, only_one_material_per_tray, program_name):
    command = CommandData(
        command=CommandEnum.LU_UNLOAD.value,
        parameter1=article_index,
        parameter2=batch,
        parameter3=laser_number,
        parameter4=laser_table_number,
        parameter5=unloading_tray,
        parameter6=ignore_laser_table_material,
        parameter7=empty_tray,
        parameter8=only_one_material_per_tray,
        parameter10=program_name
    )

    return post_blink_command(command.to_json())

def blink_unload_and_load_table(article_index, batch, laser_number, laser_table_number, unloading_tray, ignore_laser_table_material, empty_tray, only_one_material_per_tray, material_source, program_name):
    command = CommandData(
        command=CommandEnum.LU_LOADUNLOAD.value,
        parameter1=article_index,
        parameter2=batch,
        parameter3=laser_number,
        parameter4=laser_table_number,
        parameter5=unloading_tray,
        parameter6=ignore_laser_table_material,
        parameter7=empty_tray,
        parameter8=only_one_material_per_tray,
        parameter9=material_source,
        parameter10=program_name
    )

    return post_blink_command(command.to_json())    

def pretty_print_conversation(messages, last_printed_index):
    role_to_color = {
        "system": "red",
        "user": "green",
        "assistant": "blue",
        "tool": "magenta",
    }

    for i in range(last_printed_index + 1, len(messages)):
        message = messages[i]

        if isinstance(message, dict):
            role = message.get('role')
            content = message.get('content')
            
            if role == "system":
                print(colored(f"system: {content}\n", role_to_color[role]))
            elif role == "user":
                print(colored(f"user: {content}\n", role_to_color[role]))
            elif role == "assistant" and 'function_call' in message:
                function_call = message['function_call']
                print(colored(f"assistant (function call): {function_call['content']}\n", role_to_color[role]))
            elif role == "assistant" and 'content' in message:
                print(colored(f"assistant: {content}\n", role_to_color[role]))
            elif role == "tool":
                print(colored(f"function ({message['name']}): {content}\n", role_to_color[role]))
            else:
                print(colored(f"{role}: {content}\n", role_to_color.get(role, 'white')))
        else:
            inner_message = getattr(message, 'message', message)

            if isinstance(inner_message, str):
                print(colored(f"assistant: {inner_message}\n", role_to_color["assistant"]))
            else:
                role = inner_message.role
                content = inner_message.content

                if role == "system":
                    print(colored(f"system: {content}\n", role_to_color[role]))
                elif role == "user":
                    print(colored(f"user: {content}\n", role_to_color[role]))
                elif role == "assistant" and 'function_call' in inner_message:
                    function_call = inner_message['function_call']
                    print(colored(f"assistant (function call): {function_call['content']}\n", role_to_color[role]))
                elif role == "assistant" and 'content' in inner_message:
                    print(colored(f"assistant: {content}\n", role_to_color[role]))
                elif role == "tool":
                    print(colored(f"function ({inner_message['name']}): {content}\n", role_to_color[role]))
                else:
                    print(colored(f"assistant: {content}\n", role_to_color["assistant"]))  
    
tools = [
    {
    "type": "function",
    "function": {
        "name": "station_move",
        "description": "Move automatic station",
        "parameters": {
            "type": "object",
            "properties": {
                "towerNumber": {
                    "type": "integer",
                    "description": "Number of tower that contains the station"
                },
                "windowNumber": {
                    "type": "integer",
                    "description": "Number of window which is related to the station"
                },
                "stationLocation": {
                    "type": "integer",
                    "description": "Location where the station should go. 0 = go back to the tower (inside), 1 = move to location 1 (outside)"
                },                
            },
            "required": ["towerNumber", "windowNumber", "stationLocation"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "load_table",
        "description": "Load material to laser table",
        "parameters": {
            "type": "object",
            "properties": {
                "articleIndex": {
                    "type": "string",
                    "description": "Index of the article. Must be provided by the user and cannot be empty "
                },
                "batch": {
                    "type": "string",
                    "description": "Batch (optional)"
                },
                "laserNumber": {
                    "type": "integer",
                    "description": "Number of the laser"
                },
                "laserTableNumber": {
                    "type": "integer",
                    "description": "Number of the laser table (0(A)/1(B) - number of laser table)"
                },
                "materialSource": {
                    "type": "integer",
                    "description": "Material source (0 = automatic, other number = access point number)"
                },
                "ignoreLaserTableMaterial": {
                    "type": "integer",
                    "description": "Ignore laser table material (1 = loader will load material ignoring if laser table is empty or not)"
                },
            },
            "required": ["articleIndex", "laserNumber", "laserTableNumber", "materialSource", "ignoreLaserTableMaterial"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "unload_table",
        "description": "Unload material from laser table",
        "parameters": {
            "type": "object",
            "properties": {
                "articleIndex": {
                    "type": "string",
                    "description": "Index of the article (optional; if specified, it will overwrite the stored material on the laser table)"
                },
                "batch": {
                    "type": "string",
                    "description": "Batch (optional; if specified, it will overwrite the stored material on the laser table)"
                },
                "laserNumber": {
                    "type": "integer",
                    "description": "Number of the laser"
                },
                "laserTableNumber": {
                    "type": "integer",
                    "description": "Number of the laser table (0(A)/1(B) - number of laser table)"
                },
                "unloadingTray": {
                    "type": "integer",
                    "description": "Unloading tray (0 = automatic, other number = access point number/tray number)"
                },
                "ignoreLaserTableMaterial": {
                    "type": "integer",
                    "description": "Ignore laser table material (1 = unloader will unload material ignoring if laser table is empty or not)"
                },
                "emptyTray": {
                    "type": "integer",
                    "description": "Empty tray (0/1 : 1 = unload on an empty tray, 0 = use unloader settings)"
                },
                "onlyOneMaterialPerTray": {
                    "type": "integer",
                    "description": "Only one material per tray (0/1 : 1 = after unloading tray will be considered as full, 0 = use unloader settings)"
                },
                "programName": {
                    "type": "string",
                    "description": "NC program name"
                },                
            },
            "required": ["laserNumber", "laserTableNumber", "unloadingTray", "ignoreLaserTableMaterial", "emptyTray", "onlyOneMaterialPerTray", "programName"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "unload_and_load_table",
        "description": "Load and unload material",
        "parameters": {
            "type": "object",
            "properties": {
                "articleIndex": {
                    "type": "string",
                    "description": "Index of the article (Material to be loaded)"
                },
                "batch": {
                    "type": "string",
                    "description": "Batch (optional)"
                },
                "laserNumber": {
                    "type": "integer",
                    "description": "Number of the laser"
                },
                "laserTableNumber": {
                    "type": "integer",
                    "description": "Number of the laser table (0(A)/1(B) - number of laser table)"
                },
                "unloadingTray": {
                    "type": "integer",
                    "description": "Unloading tray (0 = automatic, other number = access point number/tray number)"
                },
                "ignoreLaserTableMaterial": {
                    "type": "integer",
                    "description": "Ignore laser table material (1 = unloader will unload material ignoring if laser table is empty or not)"
                },
                "emptyTray": {
                    "type": "integer",
                    "description": "Empty tray (0/1 : 1 = unload on an empty tray, 0 = use unloader settings)"
                },
                "onlyOneMaterialPerTray": {
                    "type": "integer",
                    "description": "Only one material per tray (0/1 : 1 = after unloading tray will be considered as full, 0 = use unloader settings)"
                },
                "materialSource": {
                    "type": "integer",
                    "description": "Material source (0 = automatic, other number = access point number)"
                },
                "programName": {
                    "type": "string",
                    "description": "NC program name"
                }
            },
            "required": ["articleIndex", "laserNumber", "laserTableNumber", "unloadingTray", "ignoreLaserTableMaterial", "emptyTray", "onlyOneMaterialPerTray" ,"materialSource", "programName"]
        }
    }
},
{
            "type": "function",
            "function": {
                "name": "articles",
                "description": "return all created index's with quantity",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "index": {
                            "type": "string",
                            "description": "Index of the material",
                        },
                        "name": {
                            "type": "string",
                            "description": "Name of the material",
                        },
                        "description": {
                            "type": "integer", 
                            "description": "Description of the material",
                        },
                        "artibute1": {
                            "type": "string",
                            "description": "Artibute 1 of material",
                        },
                        "artibute2": {
                            "type": "string",
                            "description": "Artibute 2 of material",
                        },
                        "artibute3": {
                            "type": "string",
                            "description": "Artibute 3 of material",
                        },
                        "dimension1": {
                            "type": "number",
                            "description": "dimension1 of material, the same what X dimension",
                        },   
                        "dimension2": {
                            "type": "number",
                            "description": "dimension2 of material, the same what Y dimension",
                        },
                        "dimension3": {
                            "type": "number",
                            "description": "dimension3 of material, the samewhat Z dimension",
                        },
                        "dimension4": {
                            "type": "number",
                            "description": "dimension4 of material",
                        },
                        "dimension5": {
                            "type": "number",
                            "description": "dimension5 of material",
                        },        
                        "dimension6": {
                            "type": "number",
                            "description": "dimension6 of material",
                        },  
                        "dimension7": {
                            "type": "number",
                            "description": "dimension7 of material",
                        },  
                        "dimension8": {
                            "type": "number",
                            "description": "dimension8 of material",
                        },    
                        "unitweight": {
                            "type": "number",
                            "description": "weight of single piece of material",
                        },   
                        "quantity": {
                            "type": "number",
                            "description": "Quantity of this material in all warehouse",
                        },
                        "minimumquantity": {
                            "type": "number",
                            "description": "Minimum quantity of this material",
                        },
                        "unit": {
                            "type": "string",
                            "description": "unit for this material",
                        },
                        "materialtype": {
                            "type": "string",
                            "description": "type of this material",
                        },
                        "category": {
                            "type": "string",
                            "description": "category of this material",
                        },
                         "storageclass": {
                            "type": "string",
                            "description": "category of this material",
                        },    
                    },
                },
            },
},
{
            "type": "function",
            "function": {
                "name": "stock",
                "description": "Get information about stock in the warehouse",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "index": {
                            "type": "string",
                            "description": "Index of the material",
                        },
                        "trayid": {
                            "type": "integer", 
                            "description": "ID of tray which contain this index",
                        },
                        "locationsymbol": {
                            "type": "string",
                            "description": "Symbol of location on the tray on which is this material",
                        },
                        "quantity": {
                            "type": "number",
                            "description": "Quantity of this material on this location",
                        },
                        "materialbatch": {
                            "type": "string",
                            "description": "batch of material on the tray",
                        },
                        "materialcertificate": {
                            "type": "string",
                            "description": "Certificate of material on the tray",
                        },
                        "materialmelt": {
                            "type": "string",
                            "description": "Melt of material on the tray",
                        },
                        "artibute1": {
                            "type": "string",
                            "description": "Artibute 1 of material on the tray",
                        },
                        "artibute2": {
                            "type": "string",
                            "description": "Artibute 2 of material on the tray",
                        },
                        "artibute3": {
                            "type": "string",
                            "description": "Artibute 3 of material on the tray",
                        },
                    },
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "tray-in-window",
                "description": "Get the current trays in all windows",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tower": {
                            "type": "integer",
                            "description": "Tower to which the window belongs",
                        },
                        "window": {
                            "type": "integer", 
                            "description": "Window to which the tray belongs",
                        },
                        "trayid": {
                            "type": "integer",
                            "description": "tray in specific window and tower",
                        },
                    },
                },
            },
        }
]

def get_views_stock():
    return get_views("stock")

def get_views_tray_in_window():
    return get_views("tray-in-window")

def get_views_articles():
    return get_views("articles")

def get_views_article_in_window():
    return get_views("article_in_window")

available_functions = {
            "station_move"          : blink_station_move,
            "load_table"            : blink_laod_table,
            "unload_table"          : blink_unload_table,
            "unload_and_load_table" : blink_unload_and_load_table,
            "articles"              : get_views_articles,
            "stock"                 : get_views_stock,
            "tray-in-window"        : get_views_tray_in_window,
            "article-in-window"     : get_views_article_in_window,}


messages = []
last_printed_index = -1
messages.append({"role": "system", "content": "Don't make assumptions about what values to plug into functions. Ask for clarification if a user request is ambiguous."})
remove_messages_after_showing = False

def flask_app():
    app.run(debug=True)

def send_to_model():
    global messages, last_printed_index, remove_messages_after_showing
    response = client.chat.completions.create(
        model= GPT_MODEL,
        messages=messages,
        tools=tools, 
    )
    response_message = response.choices[0]
    tool_calls = response_message.message.tool_calls
    if response_message.message.content is None:
        response_message.message.content = ""
    if response_message.message.function_call is None or response_message.message.function_call == "stop":
        del response_message.message.function_call

    if tool_calls:
        messages.append(response_message.message)
        for tool_call in tool_calls:
            function_name = tool_call.function.name
            function_to_call = available_functions[function_name]       
            function_args = json.loads(tool_call.function.arguments)

        if function_name == "station_move":
            function_response = function_to_call(
            tower=function_args.get("towerNumber"),
            window=function_args.get("windowNumber"),
            location=function_args.get("stationLocation"),
            )
        elif function_name == "load_table":
            function_response = function_to_call(
            article_index=function_args.get("articleIndex"),
            batch=function_args.get("batch"),
            laser_number=function_args.get("laserNumber"),
            laser_table_number=function_args.get("laserTableNumber"),
            material_source=function_args.get("materialSource"),
            ignore_laser_table_material=function_args.get("ignoreLaserTableMaterial"),
            )
        elif function_name == "unload_table":
            function_response = function_to_call(
            article_index=function_args.get("articleIndex"),
            batch=function_args.get("batch"),
            laser_number=function_args.get("laserNumber"),
            laser_table_number=function_args.get("laserTableNumber"),
            unloading_tray=function_args.get("unloadingTray"),
            ignore_laser_table_material=function_args.get("ignoreLaserTableMaterial"),
            empty_tray=function_args.get("emptyTray"),
            only_one_material_per_tray=function_args.get("onlyOneMaterialPerTray"),
            program_name=function_args.get("programName"),
                )
        elif function_name == "unload_and_load_table":
            function_response = function_to_call(
            article_index=function_args.get("articleIndex"),
            batch=function_args.get("batch"),
            laser_number=function_args.get("laserNumber"),
            laser_table_number=function_args.get("laserTableNumber"),
            unloading_tray=function_args.get("unloadingTray"),
            ignore_laser_table_material=function_args.get("ignoreLaserTableMaterial"),
            empty_tray=function_args.get("emptyTray"),
            only_one_material_per_tray=function_args.get("onlyOneMaterialPerTray"),
            material_source=function_args.get("materialSource"),
            program_name=function_args.get("programName"),
            )
        elif function_name == "tray-in-window" or function_name == "stock" or function_name == "articles":
            function_response = function_to_call()
        else:
            print(f"Unsupported function: {function_name}")
            function_response = None
        messages.append(
            {
                "tool_call_id": tool_call.id,
                "role": "tool",
                "name": function_name,
                "content": function_response,
            }       
        )

        second_response = client.chat.completions.create(
            model= GPT_MODEL,
            messages=messages,
        )
        messages.append(
            {
                "role": "assistant",
                "content": second_response.choices[0].message.content
            })
        #remove_messages_after_showing = True
    else:        
        messages.append(response_message.message)

    #pretty_print_conversation(messages, last_printed_index)
    #last_printed_index = len(messages) - 1  
    #if remove_messages_after_showing:
    #    messages = []
    #    last_printed_index = -1
    #    messages.append({"role": "system", "content": "Don't make assumptions about what values to plug into functions. Ask for clarification if a user request is ambiguous."})
    #    remove_messages_after_showing = False

flask_app()

