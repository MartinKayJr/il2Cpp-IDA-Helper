import ida_kernwin
import idc
import json


def print_banner():
    banner = """
    ==========================================
    |     Welcome to the IDA Python Script    |
    |          Developed by MartinKay         |
    ==========================================
    """
    print(banner)


def get_json_file():
    path = ida_kernwin.ask_file(0, "*.json", "Select script.json file")
    if path:
        return path
    else:
        return None

def handle(json_file):
    # 读取文件内容
    with open(json_file, 'r', encoding='utf-8') as file:
        file_content = file.read()

    # 将内容转换为 JSON 对象
    try:
        json_object = json.loads(file_content)
        method_json_obj_arr = json_object['ScriptMethod']
        handler_count = 0
        for method in method_json_obj_arr:
            addr = method['Address']
            name = method['Name']
            signature = method['Signature']
            type_signature = method['TypeSignature']
            idc.set_name(addr, name, SN_NOWARN | SN_NOCHECK)
            args_comment = f"Signature: {signature}"
            idc.set_func_cmt(addr, args_comment, 1)
            handler_count = handler_count + 1

        print("handle count: " + str(handler_count))
    except json.JSONDecodeError as e:
        print("JSON parse error:", e)

def main():
    print_banner()
    json_file = get_json_file()

    if json_file:
        handle(json_file)
        print("Method names and comments applied successfully!")
    else:
        print("No file selected!")

main()
