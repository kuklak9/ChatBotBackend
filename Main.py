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

API_URL="http://localhost:5167"
GPT_MODEL = "gpt-3.5-turbo-0613"
OPENAI_API_KEY = "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"
DB_SERVER = "192.168.0.200\\testinstance"
DB_DATABASE = "SmartWMS"
DB_USERNAME = "wms"
DB_PASSWORD = "1"

client = openai.OpenAI(api_key=OPENAI_API_KEY)
app = Flask(__name__)
CORS(app)

@app.route("/get_message", methods=["GET"])
def get_message():
    global messages
    contents = [
    {
        "role": message["role"] if isinstance(message, dict) else message.role,
        "message": message["content"] if isinstance(message, dict) and message.get("content", "") != "" else (message.content if hasattr(message, "content") and message.content != "" else None)
    }
    for message in messages
    if isinstance(message, dict) or (hasattr(message, "content") and message.content != "")
    ]
    return jsonify({"messages": contents})

@app.route("/add_message", methods=["POST"])
def add_message():
    content = request.json.get("content")
    if content is not None:
        global messages
        messages.append({"role": "user", "content": content})
        send_to_model()
        return jsonify({"success": True, "message": "Message sent successfully"}), 201
    else:
        return jsonify({"success": False, "message": "No content provided"}), 400
    
@app.route("/do_login", methods=["POST"])
def do_login():
    login = request.json.get("login")
    password = request.json.get("password")
    if login is not None and password is not None:     
        if  validate_login(login,password):
            return jsonify({"success":  True,"message": "User logged successfully"}), 201
        else:
            return jsonify({"success": False, "message": "Wrong login or password"}), 201
    else:
        return jsonify({"success": False, "message": "No login or password provided"}), 400
    
@app.route("/new_chat", methods=["POST"])
def new_chat():
    global messages
    messages = []
    messages.append({"role": "system", "content": "Don't make assumptions about what values to plug into functions. Ask for clarification if a user request is ambiguous."})
    return jsonify({"success": True, "message": "New chat initialized"}), 201

def validate_login(username, password):
    conn_str = f"DRIVER={{SQL Server}};SERVER={DB_SERVER};DATABASE={DB_DATABASE};UID={DB_USERNAME};PWD={DB_PASSWORD}"
    conn = pyodbc.connect(conn_str)
    
    cursor = conn.cursor()
    query = "SELECT * FROM Kar_Operator"
    cursor.execute(query)
    rows = cursor.fetchall()

    for row in rows:
        if row.ID_Operator == username and row.Haslo == "1NFl0EK3a+KP0UoAA4D44Q==": #do testów - szyforwanie nie działa
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
        "Content-Type": "application/json",
        "accept": "text/plain"
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

def blink_bring_item(article_index, quantity, station_location, tower, window, batch=None):
    command = CommandData(
                command=CommandEnum.BRING_ITEM.value,
                parameter1=article_index,
                parameter2=quantity,
                parameter3=batch,
                parameter8=station_location,
                parameter9=tower,
                parameter10=window)
    
    return post_blink_command(command.to_json()) 

def blink_bring_tray(tray, station_location, tower, window):
    command = CommandData(
                command=CommandEnum.BRING_TRAY.value,
                parameter1=tray,
                parameter8=station_location,
                parameter9=tower,
                parameter10=window)
    
    return post_blink_command(command.to_json()) 

def blink_bring_cut(article_index, quantity, program_name, need_empty_tray, station_location, tower, window):
    command = CommandData(
                command=CommandEnum.BRING_CUT.value,
                parameter1=article_index,
                parameter2=quantity,
                parameter3=program_name,
                parameter4=need_empty_tray,
                parameter8=station_location,
                parameter9=tower,
                parameter10=window)
    
    return post_blink_command(command.to_json()) 

def blink_bring_empty(station_location, tower, window, article_index=None, quantity=None):
    command = CommandData(
                command=CommandEnum.BRING_EMPTY.value,
                parameter1=article_index,
                parameter2=quantity,
                parameter8=station_location,
                parameter9=tower,
                parameter10=window)
    
    return post_blink_command(command.to_json()) 

def blink_pick(article_index, tray, quantity, location_symbol, batch, tower, window):
    command = CommandData(
                command=CommandEnum.PICK.value,
                parameter1=article_index,
                parameter2=tray,
                parameter3=quantity,
                parameter4=location_symbol,
                parameter5=batch,
                parameter9=tower,
                parameter10=window)
    
    return post_blink_command(command.to_json()) 

def blink_put(article_index, tray, quantity, location_symbol, batch, certificate, melt, attribute, tower, window):
    command = CommandData(
                command=CommandEnum.PUT.value,
                parameter1=article_index,
                parameter2=tray,
                parameter3=quantity,
                parameter4=location_symbol,
                parameter5=batch,
                parameter6=certificate,
                parameter7=melt,
                parameter8=attribute,
                parameter9=tower,
                parameter10=window)
    
    return post_blink_command(command.to_json()) 

def blink_put_cut(article_index, tray, quantity, location_symbol, batch, certificate, melt, program, tower, window):
    command = CommandData(
                command=CommandEnum.PUT_CUT.value,
                parameter1=article_index,
                parameter2=tray,
                parameter3=quantity,
                parameter4=location_symbol,
                parameter5=batch,
                parameter6=certificate,
                parameter7=melt,
                parameter8=program,
                parameter9=tower,
                parameter10=window)
    
    return post_blink_command(command.to_json()) 

def blink_station_move(tower, window, location):
    command = CommandData(
                command=CommandEnum.STATION_MOVE.value,
                parameter1=tower,
                parameter2=window,
                parameter3=location)
    
    return post_blink_command(command.to_json())

def blink_lu_load(article_index, laser_number, laser_table_number, material_source, ignore_laser_table_material, batch = None):
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

def blink_lu_unload( laser_number, laser_table_number, unloading_tray, ignore_laser_table_material, empty_tray, only_one_material_per_tray, program_name, article_index = None, batch = None):
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

def blink_lu_loadunload(article_index, laser_number, laser_table_number, unloading_tray, ignore_laser_table_material, empty_tray, only_one_material_per_tray, material_source, program_name, batch = None):
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

def blink_lu_resttotower(article_index, batch, laser_number, laser_table_number, tray_for_rest_of_material, dimension1, dimension2, program_name, unload_scrap_after_transport):
    command = CommandData(
        command=CommandEnum.LU_RESTTOTOWER.value,
        parameter1=article_index,
        parameter2=batch,
        parameter3=laser_number,
        parameter4=laser_table_number,
        parameter5=tray_for_rest_of_material,
        parameter6=dimension1,
        parameter7=dimension2,
        parameter8=program_name,
        parameter9=unload_scrap_after_transport,
        parameter10=program_name
    )

    return post_blink_command(command.to_json())    

def blink_lu_pickunloadtray(tray, tower, window):
    command = CommandData(
        command=CommandEnum.LU_PICKUNLOADTRAY.value,
        parameter1=tray,
        parameter9=tower,
        parameter10=window,
    )

    return post_blink_command(command.to_json())    

def blink_lu_prepare(article_index, batch, tray, load, unload, laser_number, laser_table_number, transport_to_station, program_name):
    command = CommandData(
        command=CommandEnum.LU_PREPARE.value,
        parameter1=article_index,
        parameter2=batch,
        parameter3=tray,
        parameter4=load,
        parameter5=unload,
        parameter6=laser_number,
        parameter7=laser_table_number,
        parameter8=transport_to_station,
        parameter9=program_name,
    )

    return post_blink_command(command.to_json())    

def get_views_stock():
    return get_views("stock")

def get_views_tray_in_window():
    return get_views("tray-in-window")

def get_views_articles():
    return get_views("articles")

def get_views_article_in_window():
    return get_views("article_in_window")

tools = [
{
    "type": "function",
    "function": {
        "name": "bring_item",
        "description": ("Powoduje transport półki, która posiada podany indeks materiału i co najmniej ilość arkuszy podaną w zapytaniu."
                        "Transport ten odbywa się na wskazane okno we wskazanym regale."),
        "parameters": {
            "type": "object",
            "properties": {
                "article_index": {
                    "type": "string",
                    "description": "Indeks materiału, który znajduje się na półke, którą chcemy przywieźć na wskazane okno. Przykład 'DC01_3000X1500X1'."
                },
                "quantity": {
                    "type": "integer",
                    "description": "Minimalna ilość materiału, która powinna znajadować się na przywożonej półce."
                },
                "batch": {
                    "type": "string",
                    "description": "Partia, do której należy przywożony materiał."
                },
                "station_location": {
                    "type": "integer",
                    "description": ("Jeżeli we wskazanym oknie wstępuje stacja automatyczna to przez ten parametr określana jest pozycja,"
                                    "w której ma się znajdować ta stacja po przywiezieniu półki."
                                    "1 oznacza jazdę stacji na pozycję na zewnątrz regału, 0 oznacza pozostanie w regale.")
                },       
                "tower": {
                    "type": "integer",
                    "description": "Numer regału, do którego należy okno, na które na zostać przywieziona pólka z materiałem."
                },
                "window": {
                    "type": "integer",
                    "description": "Numer okna, do któego ma się odbyc trasport półki"
                },
         
            },
            "required": ["article_index", "quantity", "station_location", "tower", "window"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "bring_tray",
        "description": "Powoduje transport półki o wskazanym numerze. Transport ten odbywa się na wskazane okno we wskazanym regale.",
        "parameters": {
            "type": "object",
            "properties": {
                "tray": {
                    "type": "integer",
                    "description": "Numer półki, która ma zostać przwieziona na okno."
                },
                "station_location": {
                    "type": "integer",
                    "description": ("Jeżeli we wskazanym oknie wstępuje stacja automatyczna to przez ten parametr określana jest pozycja,"
                                    "w której ma się znajdować ta stacja po przywiezieniu półki."
                                    "1 oznacza jazdę stacji na pozycję na zewnątrz regału, 0 oznacza pozostanie w regale.")
                },       
                "tower": {
                    "type": "integer",
                    "description": "Numer regału, do którego należy okno, na które na zostać przywieziona pólka z materiałem."
                },
                "window": {
                    "type": "integer",
                    "description": "Numer okna, do któego ma się odbyc trasport półki"
                },
         
            },
            "required": ["tray", "station_location", "tower", "window"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "bring_cut",
        "description": ("Powoduje transport półki, która może przyjąć wycięty materiał o podanym indeksie."
                        "Wyszukiwanie półki do transportu odbywa się na podstawie podanego indeksu i nazwy programu za pomocą którego wycięty został materiał."
                        "Możliwe jest wymaganie pustej półki."
                        "Transport ten odbywa się na wskazane okno we wskazanym regale.",
                        ),
        "parameters": {
            "type": "object",
            "properties": {
                "article_index": {
                    "type": "string",
                    "description": "Indeks wyciętego materiału, który chcemy położyć na przywożonej półce. Przykład 'C_DC01_3000X1500X1'."
                },
                "quantity": {
                    "type": "integer",
                    "description": "Ilość wyciętych arkuszy o wskazanym indeksie, które chcemy położyć na przywożonej półce."
                },
                "program_name": {
                    "type": "string",
                    "description": "Nazwa programu, którym wycięty został wskazany materiał."
                },  
                "need_empty_tray": {
                    "type": "integer",
                    "description": "Należy podać wartość 1 jeżeli przywieziona ma zostać pusta półka."
                },   
                "station_location": {
                    "type": "integer",
                    "description": ("Jeżeli we wskazanym oknie wstępuje stacja automatyczna to przez ten parametr określana jest pozycja,"
                                    "w której ma się znajdować ta stacja po przywiezieniu półki."
                                    "1 oznacza jazdę stacji na pozycję na zewnątrz regału, 0 oznacza pozostanie w regale.")
                },      
                "tower": {
                    "type": "integer",
                    "description": "Numer regału, do którego należy okno, na które na zostać przywieziona pólka z materiałem."
                },
                "window": {
                    "type": "integer",
                    "description": "Numer okna, do któego ma się odbyc trasport półki"
                },
         
            },
            "required": ["article_index", "quantity", "program_name", "need_empty_tray", "station_location", "tower", "window"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "bring_empty",
        "description": "Powoduje transport pustej półki. Transport ten odbywa się na wskazane okno we wskazanym regale.",
        "parameters": {
            "type": "object",
            "properties": {
                "article_index": {
                    "type": "string",
                    "description": "Indeks materiału, który chcemy położyć na przywożonej pustej półce. Przykład 'DC01_3000X1500X1'."
                },
                "quantity": {
                    "type": "integer",
                    "description": "Ilość arkuszy o wskazanym indeksie, które chcemy położyć na przywożonej pustej półce."
                },
                "station_location": {
                    "type": "integer",
                    "description": ("Jeżeli we wskazanym oknie wstępuje stacja automatyczna to przez ten parametr określana jest pozycja,"
                                    "w której ma się znajdować ta stacja po przywiezieniu półki."
                                    "1 oznacza jazdę stacji na pozycję na zewnątrz regału, 0 oznacza pozostanie w regale.")
                },      
                "tower": {
                    "type": "integer",
                    "description": "Numer regału, do którego należy okno, na które na zostać przywieziona pólka z materiałem."
                },
                "window": {
                    "type": "integer",
                    "description": "Numer okna, do któego ma się odbyc trasport półki"
                },
         
            },
            "required": ["station_location", "tower", "window"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "pick",
        "description": ("Powoduje poinformowanie systemu o pobraniu materiału i zaktualizowanie jego ilości."
                        "Gdy podana ilość materiału będzie większa bądź równa ilości na półce, materiał zostanie z niej usunięty."),
        "parameters": {
            "type": "object",
            "properties": {
                "article_index": {
                    "type": "string",
                    "description": "Indeks materiału, który został pobrany z magazynu. Przykład 'DC01_3000X1500X1'."
                },
                "tray": {
                    "type": "integer",
                    "description": "Numer półki, z której został ten materiał pobrany"
                },
                "quantity": {
                    "type": "integer",
                    "description": "Ilość materiału, która została pobrana z podanej półki."
                },
                "location_symbol": {
                    "type": "string",
                    "description": "Symbol lokalizacji na półce, z której materiał został pobrany. Wymagane gdy system używa lokalizacji."
                },
                "batch": {
                    "type": "string",
                    "description": "Partia, do której należy pobierany materiał."
                }, 
                "tower": {
                    "type": "integer",
                    "description": "Numer regału, przy którym nastapiła operacja pobrania materiału."
                },
                "window": {
                    "type": "integer",
                    "description": "Numer okna, przy którym nastapiła operacja pobrania materiału."
                },
         
            },
            "required": ["article_index", "tray", "quantity", "tower", "window"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "put",
        "description": "Powoduje poinformowanie systemu o włożeniu materiału i zaktualizowanie jego ilości.",
        "parameters": {
            "type": "object",
            "properties": {
                "article_index": {
                    "type": "string",
                    "description": "Indeks materiału, który został pobrany z magazynu. Przykład 'DC01_3000X1500X1'."
                },
                "tray": {
                    "type": "integer",
                    "description": "Numer półki, z której został ten materiał pobrany"
                },
                "quantity": {
                    "type": "integer",
                    "description": "Ilość materiału, która została pobrana z podanej półki."
                },
                "location_symbol": {
                    "type": "string",
                    "description": "Symbol lokalizacji na półce, z której materiał został pobrany. Wymagane gdy system używa lokalizacji."
                },
                "batch": {
                    "type": "string",
                    "description": "Partia, do której należy pobierany materiał."
                }, 
                "certificate": {
                    "type": "string",
                    "description": "Nazwa atestu, jeżeli materiał go posiada."
                }, 
                "melt": {
                    "type": "string",
                    "description": "Nazwa wytopu, jeżeli materiał go posiada."
                }, 
                "attribute": {
                    "type": "string",
                    "description": "Nazwa atrybutu, jeżeli materiał go posiada."
                }, 
                "tower": {
                    "type": "integer",
                    "description": "Numer regału, przy którym nastapiła operacja włożenia materiału."
                },
                "window": {
                    "type": "integer",
                    "description": "Numer okna, przy którym nastapiła operacja włożenia materiału."
                },
         
            },
            "required": ["article_index", "tray", "quantity", "tower", "window"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "put_cut",
        "description": ("Powoduje poinformowanie systemu o włożeniu wyciętego materiału i zaktualizowanie jego ilości."
                        "Dla podanego indeksu i nazwy programu utworzony zostanie automatycznie nowy indeks."),
        "parameters": {
            "type": "object",
            "properties": {
                "article_index": {
                    "type": "string",
                    "description": "Indeks materiału, który został pobrany z magazynu. Przykład 'DC01_3000X1500X1'."
                },
                "tray": {
                    "type": "integer",
                    "description": "Numer półki, z której został ten materiał pobrany"
                },
                "quantity": {
                    "type": "integer",
                    "description": "Ilość materiału, która została pobrana z podanej półki."
                },
                "location_symbol": {
                    "type": "string",
                    "description": "Symbol lokalizacji na półce, z której materiał został pobrany. Wymagane gdy system używa lokalizacji."
                },
                "batch": {
                    "type": "string",
                    "description": "Partia, do której należy pobierany materiał."
                }, 
                "certificate": {
                    "type": "string",
                    "description": "Nazwa atestu, jeżeli materiał go posiada."
                }, 
                "melt": {
                    "type": "string",
                    "description": "Nazwa wytopu, jeżeli materiał go posiada."
                }, 
                "program_name": {
                    "type": "string",
                    "description": "Nazwa programu, którym wycięty został wskazany materiał."
                },  
                "tower": {
                    "type": "integer",
                    "description": "Numer regału, przy którym nastapiła operacja włożenia materiału."
                },
                "window": {
                    "type": "integer",
                    "description": "Numer okna, przy którym nastapiła operacja włożenia materiału."
                },
         
            },
            "required": ["article_index", "tray", "quantity", "tower", "window"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "station_move",
        "description": "Ruch stacji automatycznej na wskazaną lokalizację.",
        "parameters": {
            "type": "object",
            "properties": {
                "tower": {
                    "type": "integer",
                    "description": "Numer regału,do którego należy stacja automatyczna."
                },
                "window": {
                    "type": "integer",
                    "description": "Numer okna, do którego przypisana jest stacja."
                },
                "location": {
                    "type": "integer",
                    "description": ("Lokalizacja do której chcemy ruszyć stacją."
                                    "0 oznacza powórt stacji do regału, a 1 oznacza wyjechanie stacją na pozycję zewnętrzą."
                                    "Możliwy jest ruch na lokalizację inne niz 0 i 1.")
                },                
            },
            "required": ["tower", "window", "location"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "lu_load",
        "description": "Żądanie załadowania podanego stołu lasera materiałem o podanym indeksie.",
        "parameters": {
            "type": "object",
            "properties": {
                "article_index": {
                    "type": "string",
                    "description": "Indeks materiału, który ma zostać załadowany na stół lasera. Przykład 'DC01_3000X1500X1'"
                },
                "batch": {
                    "type": "string",
                    "description": "Partia, z której pochodzi żądany materiał."
                },
                "laser_number": {
                    "type": "integer",
                    "description": "Numer lasera, którego stołu dotyczy to żądanie."
                },
                "laser_table_number": {
                    "type": "integer",
                    "description": ("Numer stołu podanego wcześniej lasera, na który ma zostać załadowany materiał o podanym indeksie."
                                    "Stół A oznacza stół o numerze 0, a stół B oznacza stół o numerze 1."),
                },
                "material_source": {
                    "type": "integer",
                    "description": ("Źródło pochodzenia materiału. 0, gdy system sam ma zdecydować skąd pobrać materiał." 
                                    "Różne od 0, gdy chcemy sami wspacać z któego punktu dostępowego ma zostać pobrany ten materiał.")
                },
                "ignore_laser_table_material": {
                    "type": "integer",
                    "description": ("Wartość 0, gdy system ma odrzucać żądanie, gdy ma już zdefiniowany materiał na żądanym stole."
                                    "Wartość 1, gdy ma mimo wszytsko wykonać żądanie - może to spowodować położenie kliku blach na stole lasera"
                                    "lub położenie surowego materiału na materiale wyciętym")
                },
            },
            "required": ["article_index", "laser_number", "laser_table_number", "material_source", "ignore_laser_table_material"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "lu_unload",
        "description": "Żądanie rozładowania podanego stołu lasera.",
        "parameters": {
            "type": "object",
            "properties": {
                "article_index": {
                    "type": "string",
                    "description": ("Indeks materiału, który ma być rozładowany."
                                    "Jeżeli jest podany to nadpisuje indeks materiału, który znajduje się na podanym stole lasera.")
                },
                "batch": {
                    "type": "string",
                    "description": ("Partaia, do któej należy wycięty materiał."
                                    "Jeżeli jest podana to nadpisuje partię materiału, który znajduje się na podanym stole lasera.")
                },
                "laser_number": {
                    "type": "integer",
                    "description": "Numer lasera, którego stołu dotyczy to żądanie."
                },
                "laser_table_number": {
                    "type": "integer",
                    "description": "Numer stołu podanego wcześniej lasera, z którego ma zostać rozładowany materiał."
                                    "Stół A oznacza stół o numerze 0, a stół B oznacza stół o numerze 1."
                },
                "unloading_tray": {
                    "type": "integer",
                    "description": "Półka, na która ma być rozładowany materiał. 0 oznacza wybrób pólki automatycznie przez system."
                                   "Numer różny od 0 zoancza rozłądunek na półkę o podanym tutaj numerze."
                },
                "ignore_laser_table_material": {
                    "type": "integer",
                    "description": "Wartość 0, gdy system ma odrzucać żądanie, gdy nie ma zdefiniowanego materiał na żądanym stole."
                                    "Wartość 1, gdy ma mimo wszytsko wykonać żądanie"
                },
                "empty_tray": {
                    "type": "integer",
                    "description": "Wartość 1 gdy materiał ma zostać rozładowany na pustą półkę, wartość 0 gdy nie musi."
                },
                "only_one_material_per_tray": {
                    "type": "integer",
                    "description": "Wartość 1 spowoduje zablokwoanie półki po rozładunku, wartość 0 nie zablokuje półki po rozładunku."
                },
                "program_name": {
                    "type": "string",
                    "description": "Nazwa progrmau, którym został wyvięty materiał znajdujący się na żądanym stole."
                },                
            },
            "required": ["laser_number", "laser_table_number", "unloading_tray", "ignore_laser_table_material", "empty_tray", "only_one_material_per_tray", "program_name"]
        }
    }
},
{
    "type": "function",
    "function": {
        "name": "lu_loadunload",
        "description": "Żądanie rozładowania i załadowania stółu materiąłem o wybranym indeksie, za pomoca jednej komendy.",
        "parameters": {
            "type": "object",
            "properties": {
                "article_index": {
                    "type": "string",
                    "description": "Indeks materiału, który ma zostać załadowany na stół lasera. Przykład 'DC01_3000X1500X1'."
                },
                "batch": {
                    "type": "string",
                    "description": "Partia, z której pochodzi żądany materiał."
                },
                "laser_number": {
                    "type": "integer",
                    "description": "Numer lasera, którego stołu dotyczy to żądanie."
                },
                "laser_table_number": {
                    "type": "integer",
                    "description": ("Numer stołu podanego wcześniej lasera, na który ma zostać rozładowany,"
                                    "a nastepnie załadowany materiał o podanym indeksie."
                                    "Stół A oznacza stół o numerze 0, a stół B oznacza stół o numerze 1."),
                },
                "unloading_tray": {
                    "type": "integer",
                    "description": "Półka, na która ma być rozładowany materiał. 0 oznacza wybrób pólki automatycznie przez system."
                                   "Numer różny od 0 zoancza rozłądunek na półkę o podanym tutaj numerze."
                },
                "ignore_laser_table_material": {
                    "type": "integer",
                    "description": "Wartość 0, gdy system ma odrzucać żądanie, gdy nie ma zdefiniowanego materiał na żądanym stole."
                                    "Wartość 1, gdy ma mimo wszytsko wykonać żądanie"
                },
                "empty_tray": {
                    "type": "integer",
                    "description": "Wartość 1 gdy materiał ma zostać rozładowany na pustą półkę, wartość 0 gdy nie musi."
                },
                "only_one_material_per_tray": {
                    "type": "integer",
                    "description": "Wartość 1 spowoduje zablokwoanie półki po rozładunku, wartość 0 nie zablokuje półki po rozładunku."
                },
                "material_source": {
                    "type": "integer",
                    "description": ("Źródło pochodzenia materiału. 0, gdy system sam ma zdecydować skąd pobrać materiał." 
                                    "Różne od 0, gdy chcemy sami wspacać z któego punktu dostępowego ma zostać pobrany ten materiał.")
                },
                "program_name": {
                    "type": "string",
                    "description": "Nazwa progrmau, którym został wyvięty materiał znajdujący się na żądanym stole."
                },           
            },
            "required": ["article_index", "laser_number", "laser_table_number", "unloading_tray", "ignore_laser_table_material", "empty_tray", "only_one_material_per_tray" ,"material_source", "program_name"]
        }
    }
},
{
            "type": "function",
            "function": {
                "name": "articles",
                "description": "Zwraca wszytskie obecne w systemie indeksy wraz z ilością w jakiej są obecne w systemie.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "index": {
                            "type": "string",
                            "description": "Indeks",
                        },
                        "name": {
                            "type": "string",
                            "description": "Nazwa",
                        },
                        "description": {
                            "type": "integer", 
                            "description": "Opis",
                        },
                        "artibute1": {
                            "type": "string",
                            "description": "Atrybut 1",
                        },
                        "artibute2": {
                            "type": "string",
                            "description": "Atrybut 2",
                        },
                        "artibute3": {
                            "type": "string",
                            "description": "Atrybut 3",
                        },
                        "dimension1": {
                            "type": "number",
                            "description": "Wymiar1, to samo co Wymiar X, podawany w jednostce określonej w parametrze jednostka",
                        },   
                        "dimension2": {
                            "type": "number",
                            "description": "Wymiar2, to samo co Wymiar Y, podawany w jednostce określonej w parametrze jednostka",
                        },
                        "dimension3": {
                            "type": "number",
                            "description": "Wymiar3, to samo co Wymiar Z, podawany w jednostce określonej w parametrze jednostka",
                        },
                        "dimension4": {
                            "type": "number",
                            "description": "Wymiar4, podawany w jednostce określonej w parametrze jednostka",
                        },
                        "dimension5": {
                            "type": "number",
                            "description": "Wymiar5, podawany w jednostce określonej w parametrze jednostka",
                        },        
                        "dimension6": {
                            "type": "number",
                            "description": "Wymiar6, podawany w jednostce określonej w parametrze jednostka",
                        },  
                        "dimension7": {
                            "type": "number",
                            "description": "Wymiar7, podawany w jednostce określonej w parametrze jednostka",
                        },  
                        "dimension8": {
                            "type": "number",
                            "description": "Wymiar8, podawany w jednostce określonej w parametrze jednostka",
                        },    
                        "unitweight": {
                            "type": "number",
                            "description": "Waga pojedyńczego arkusza",
                        },   
                        "quantity": {
                            "type": "number",
                            "description": "Ilość materiału o tym indeksie w całym magazynie",
                        },
                        "minimumquantity": {
                            "type": "number",
                            "description": "Wymagana minimalna ilość tego materiału",
                        },
                        "unit": {
                            "type": "string",
                            "description": "Jednostka",
                        },
                        "materialtype": {
                            "type": "string",
                            "description": "Gatunek",
                        },
                        "category": {
                            "type": "string",
                            "description": "Kategoria",
                        },
                         "storageclass": {
                            "type": "string",
                            "description": "Klasa składowania",
                        },    
                    },
                },
            },
},
{
            "type": "function",
            "function": {
                "name": "stock",
                "description": "Zwraca aktualny stan magazynowy, czyl inforamcję o tym jaki materiał w jakiej ilości jest na jakiej półce i jakiej lokalizacji.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "index": {
                            "type": "string",
                            "description": "Indeks materiału",
                        },
                        "trayid": {
                            "type": "integer", 
                            "description": "Numer półki",
                        },
                        "locationsymbol": {
                            "type": "string",
                            "description": "Symbol lokalizacji na półce",
                        },
                        "quantity": {
                            "type": "number",
                            "description": "Ilość na lokalizacji",
                        },
                        "materialbatch": {
                            "type": "string",
                            "description": "Partia materiału",
                        },
                        "materialcertificate": {
                            "type": "string",
                            "description": "Certyfikat",
                        },
                        "materialmelt": {
                            "type": "string",
                            "description": "Wytop",
                        },
                        "artibute1": {
                            "type": "string",
                            "description": "Atrybut 1",
                        },
                        "artibute2": {
                            "type": "string",
                            "description": "Atrybut 2",
                        },
                        "artibute3": {
                            "type": "string",
                            "description": "Atrybut 3",
                        },
                    },
                },
            },
        },
{
            "type": "function",
            "function": {
                "name": "tray-in-window",
                "description": "Zwraca numery półek w oknach ",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "tower": {
                            "type": "integer",
                            "description": "Regał do którego należy okno",
                        },
                        "window": {
                            "type": "integer", 
                            "description": "Półka w której lezy półka",
                        },
                        "trayid": {
                            "type": "integer",
                            "description": "Numer półki w oknie",
                        },
                    },
                },
            },
        }
]

def call_function(function_name, function_args):
    if function_name in available_functions:
        function_to_call = available_functions[function_name]
        function_response = function_to_call(**function_args)
        return function_response
    else:
        return f"Error: Function {function_name} not available."

available_functions = {
            "bring_item"            : blink_bring_item,
            "bring_tray"            : blink_bring_tray,
            "bring_empty"           : blink_bring_empty,
            "bring_cut"             : blink_bring_cut,
            "pick"                  : blink_pick,
            "put"                   : blink_put,
            "put_cut"               : blink_put_cut,
            "station_move"          : blink_station_move,
            "lu_load"               : blink_lu_load,
            "lu_unload"             : blink_lu_unload,
            "lu_loadunload"         : blink_lu_loadunload,
            "lu_pickunloadtray"     : blink_lu_pickunloadtray,
            "lu_prepare"            : blink_lu_prepare,
            "articles"              : get_views_articles,
            "stock"                 : get_views_stock,
            "tray-in-window"        : get_views_tray_in_window,
            "article-in-window"     : get_views_article_in_window,}


messages = []
last_printed_index = -1
messages.append({"role": "system", "content": "Don't make assumptions about what values to plug into functions. Ask for clarification if a user request is ambiguous."})

def flask_app():
    app.run(debug=True)

def send_to_model():
    global messages
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
            function_args = json.loads(tool_call.function.arguments)

            function_response = call_function(function_name, function_args)

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
    else:        
        messages.append(response_message.message)


flask_app()

