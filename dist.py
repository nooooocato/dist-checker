# -*- coding: utf-8 -*-

import os
import zipfile
import argparse
import re
import shutil
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

def get_mod_metadata(zf: zipfile.ZipFile, toml_content: str) -> dict:
    """從 mods.toml 內容中解析出 modId 和依賴列表（包含 side）。"""
    metadata = {'modId': None, 'dependencies': []}
    
    main_mod_id_match = re.search(r'modId\s*=\s*["\'](.+?)["\']', toml_content)
    if main_mod_id_match:
        metadata['modId'] = main_mod_id_match.group(1)

    dependency_blocks = re.findall(r'(\[\[dependencies\..+?\]\][\s\S]+?)(?=\n\[\[|$)', toml_content)
    
    for block in dependency_blocks:
        dep_id_match = re.search(r'modId\s*=\s*["\'](.+?)["\']', block)
        if not dep_id_match:
            continue
        
        dep_id = dep_id_match.group(1)
        side = "BOTH" 
        
        side_match = re.search(r'side\s*=\s*["\'](.+?)["\']', block, re.IGNORECASE)
        if side_match:
            side = side_match.group(1).upper()
            
        metadata['dependencies'].append({'modId': dep_id, 'side': side})

    return metadata

def analyze_code_references(zf: zipfile.ZipFile) -> dict:
    """
    掃描 JAR 中的 .class 檔案，搜索 Forge 文件中提到的特定程式碼引用簽名。
    """
    findings = {
        'has_level_isclientside': False,
        'has_distexecutor_client': False,
        'has_distexecutor_server': False,
        'has_onlyin_client': False,
        'has_onlyin_server': False,
        'has_fmlenvironment_dist': False,
        'has_generic_client_ref': False,
        'has_server_ref': False,
    }

    # 定義要搜索的位元組碼簽名
    isclientside_sig = b'isClientSide' 
    level_class_sig = b'Lnet/minecraft/world/level/Level;'
    distexecutor_sig = b'Lnet/minecraftforge/fml/DistExecutor;'
    onlyin_sig = b'Lnet/minecraftforge/api/distmarker/OnlyIn;'
    dist_sig = b'Lnet/minecraftforge/api/distmarker/Dist;'
    client_enum_sig = b'CLIENT'
    server_enum_sig = b'SERVER'
    fmlenv_sig = b'Lnet/minecraftforge/fml/loading/FMLEnvironment;'
    generic_client_sig = b'net/minecraft/client/'
    server_sig = b'net/minecraft/server/level/'

    class_files = [name for name in zf.namelist() if name.lower().endswith('.class')]
    for filename in class_files:
        try:
            with zf.open(filename) as class_file:
                content = class_file.read()
                
                if not findings['has_level_isclientside'] and isclientside_sig in content and level_class_sig in content:
                    findings['has_level_isclientside'] = True
                
                if distexecutor_sig in content and dist_sig in content:
                    if not findings['has_distexecutor_client'] and client_enum_sig in content:
                        findings['has_distexecutor_client'] = True
                    if not findings['has_distexecutor_server'] and server_enum_sig in content:
                        findings['has_distexecutor_server'] = True
                
                if onlyin_sig in content and dist_sig in content:
                    if not findings['has_onlyin_client'] and client_enum_sig in content:
                        findings['has_onlyin_client'] = True
                    if not findings['has_onlyin_server'] and server_enum_sig in content:
                        findings['has_onlyin_server'] = True

                if not findings['has_fmlenvironment_dist'] and fmlenv_sig in content:
                    findings['has_fmlenvironment_dist'] = True
                if not findings['has_generic_client_ref'] and generic_client_sig in content:
                    findings['has_generic_client_ref'] = True
                if not findings['has_server_ref'] and server_sig in content:
                    findings['has_server_ref'] = True

                if all(f for f in findings.values() if isinstance(f, bool)):
                    break
        except Exception:
            continue
    return findings

def initial_classify(zf: zipfile.ZipFile, toml_content: str, namelist: list) -> (str, str):
    """根據深度程式碼特徵，對單個 Mod 進行初步分類。"""
    if re.search(r'displayTest\s*=\s*["\']CLIENT_ONLY["\']', toml_content, re.IGNORECASE):
        return "僅客戶端", "mods.toml 明確指定 (displayTest)"
    
    if '[[exports]]' in toml_content:
        return "API / 函式庫", "mods.toml 中定義了 exports"

    description_str = ""
    match = re.search(r'description\s*=\s*(?:"""([\s\S]*?)"""|\'\'\'([\s\S]*?)\'\'\'|"((?:\\.|[^"\\])*)"|\'((?:\\.|[^"\\])*)\')', toml_content, re.IGNORECASE)
    if match:
        description_str = next((s for s in match.groups() if s is not None), "")
    
    if description_str and ('api' in description_str.lower() or 'library' in description_str.lower()):
        return "API / 函式庫", "description 中包含 'API' 或 'Library' 字樣"

    code_analysis = analyze_code_references(zf)
    has_assets = any(name.startswith('assets/') for name in namelist)
    has_api_folder = any('/api/' in name.lower() for name in namelist)

    has_client_features = (
        code_analysis['has_distexecutor_client'] or
        code_analysis['has_onlyin_client'] or
        code_analysis['has_generic_client_ref'] or
        code_analysis['has_fmlenvironment_dist']
    )
    has_server_features = (
        code_analysis['has_distexecutor_server'] or
        code_analysis['has_onlyin_server'] or
        code_analysis['has_server_ref']
    )
    has_logical_side_check = code_analysis['has_level_isclientside']
    
    if has_logical_side_check or (has_client_features and has_server_features):
        reason = "檢測到雙端程式碼特性"
        if has_logical_side_check: 
            reason += " (含 Level#isClientSide 調用)"
        else: 
            reason += " (同時包含客戶端與伺服器端特徵)"
        return "雙端", reason
        
    if not has_assets:
        if has_client_features:
            return "僅客戶端", "無 assets 但僅檢測到客戶端專有程式碼"
        else:
            return "僅伺服器端", "缺少 assets 且無客戶端程式碼信號"

    if has_client_features:
        return "雙端", "有 assets 並檢測到客戶端程式碼"
        
    if has_api_folder:
         return "API / 函式庫", "有 assets 和 api 資料夾但無客戶端程式碼"
         
    return "雙端", "有 assets 但無明確的客戶端程式碼 (可能為資源包)"

def write_log_file(output_path: Path, all_mods_info: dict, scanned_dir: Path):
    """將詳細的分析結果寫入日誌檔案。"""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write(" Minecraft Mod 分類分析報告\n")
        f.write("=" * 80 + "\n")
        f.write(f"掃描時間: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"掃描目錄: {scanned_dir.resolve()}\n")
        f.write("-" * 80 + "\n\n")

        classification_counter = Counter()

        for filename, info in sorted(all_mods_info.items(), key=lambda item: item[0].lower()):
            f.write(f"--- {filename} ---\n")
            f.write(f"  - Mod ID            : {info.get('modId', '無法解析')}\n")
            
            deps = info.get('dependencies', [])
            if deps:
                f.write("  - 依賴項 (Dependencies):\n")
                for dep in deps:
                    f.write(f"    - {dep['modId']} (side={dep['side']})\n")
            else:
                f.write("  - 依賴項 (Dependencies): 無\n")

            f.write("\n  - 分析鏈路:\n")
            f.write(f"    1. 初步分析: {info['initial_classification']} [依據: {info['initial_reason']}]\n")
            
            if info['was_corrected']:
                f.write(f"    2. 依賴校正: 分類被修正，因為 {info['correction_reason']}\n")
                f.write(f"    3. 最終結論: {info['final_classification']}\n")
            else:
                f.write(f"    2. 依賴校正: 無需修正\n")
                f.write(f"    3. 最終結論: {info['final_classification']}\n")
            
            f.write("\n" + "-" * 40 + "\n\n")
            classification_counter[info['final_classification']] += 1
        
        f.write("\n" + "=" * 80 + "\n")
        f.write(" 分析結果總結\n")
        f.write("=" * 80 + "\n")
        for classification, count in sorted(classification_counter.items()):
            f.write(f"- {classification:<25} : {count} 個\n")
        f.write("-" * 80 + "\n")

def main():
    parser = argparse.ArgumentParser(
        description="一個 Python 腳本，用於根據 JAR 結構和深度程式碼特徵來分類 Minecraft Forge Mod，並輸出詳細日誌及歸檔檔案。",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
使用範例:
  # 僅分析並生成日誌
  python %(prog)s "C:\\mods"

  # 分析、生成日誌並將檔案複製到 'output' 資料夾
  python %(prog)s "C:\\mods" -c "C:\\mods\\output"
"""
    )
    parser.add_argument("mods_directory", type=str, help="包含 .jar Mod 檔案的資料夾路徑。")
    parser.add_argument("-c", "--copy-to", type=str, help="將分類後的 Mod 檔案複製到指定的父級目錄下。日誌也會存放在此。")
    args = parser.parse_args()
    
    mods_dir = Path(args.mods_directory)
    copy_output_dir = Path(args.copy_to) if args.copy_to else None
    
    # 決定日誌檔案的路徑
    if copy_output_dir:
        output_log_path = copy_output_dir / "mod_classification_log.txt"
    else:
        output_log_path = Path("mod_classification_log.txt")

    if not mods_dir.is_dir():
        print(f"\n錯誤：提供的路徑 '{mods_dir}' 不是一個有效的資料夾。")
        return

    print("=" * 80)
    print(f"[*] 正在掃描資料夾: {mods_dir.resolve()}")
    if copy_output_dir:
        print(f"[*] 檔案將被歸檔至: {copy_output_dir.resolve()}")
    print(f"[*] 分析日誌將儲存至: {output_log_path.resolve()}")
    print("=" * 80)

    # --- 歸檔目錄設置 ---
    category_folders = {
        "僅客戶端": "1_Client_Side",
        "僅伺服器端": "2_Server_Side",
        "雙端": "3_Both_Universal",
        "API / 函式庫": "4_API_Library",
        "錯誤": "5_Errors",
    }
    if copy_output_dir:
        copy_output_dir.mkdir(parents=True, exist_ok=True)
        for folder_name in category_folders.values():
            (copy_output_dir / folder_name).mkdir(exist_ok=True)

    all_mods_info = {}
    mod_id_to_filename = {}
    jar_files = [f for f in sorted(os.listdir(mods_dir), key=str.lower) if f.lower().endswith('.jar')]
    
    IGNORED_DEPENDENCIES = ['minecraft', 'forge']

    print("[階段 1] 正在收集 Mod 資訊與初步分類...")
    for filename in jar_files:
        jar_path = mods_dir / filename
        try:
            with zipfile.ZipFile(jar_path, 'r') as zf:
                namelist = zf.namelist()
                toml_content = ""
                if 'META-INF/mods.toml' in namelist:
                    with zf.open('META-INF/mods.toml') as toml_file:
                        toml_content = toml_file.read().decode('utf-8', errors='ignore')

                metadata = get_mod_metadata(zf, toml_content)
                initial_classification, initial_reason = initial_classify(zf, toml_content, namelist)
                
                all_mods_info[filename] = {
                    'modId': metadata['modId'],
                    'dependencies': metadata['dependencies'],
                    'initial_classification': initial_classification,
                    'initial_reason': initial_reason,
                    'final_classification': initial_classification,
                    'was_corrected': False,
                    'correction_reason': ''
                }
                if metadata['modId']:
                    mod_id_to_filename[metadata['modId']] = filename
        except (zipfile.BadZipFile, OSError) as e:
            all_mods_info[filename] = {
                'initial_classification': '錯誤', 'initial_reason': f'無法讀取 JAR ({e})',
                'final_classification': '錯誤', 'was_corrected': False
            }
    
    print(f"[階段 1] 完成，共分析 {len(jar_files)} 個檔案。\n")
    
    print("[階段 2] 正在根據依賴關係進行校正...")
    corrections_made = 0
    for filename in jar_files:
        if filename not in all_mods_info or all_mods_info[filename]['initial_classification'] == '錯誤':
            continue

        info = all_mods_info[filename]
        if info['initial_classification'] in ["僅伺服器端", "僅客戶端"]:
            for dep_dict in info.get('dependencies', []):
                dep_id = dep_dict.get('modId')
                
                if dep_id in IGNORED_DEPENDENCIES:
                    continue

                dep_side = dep_dict.get('side', 'BOTH').upper()
                correction_made_for_this_mod = False

                if dep_side == 'BOTH':
                    info['final_classification'] = "雙端"
                    info['correction_reason'] = f"其依賴項 '{dep_id}' 被明確要求為 side=BOTH"
                    info['was_corrected'] = True
                    corrections_made += 1
                    correction_made_for_this_mod = True
                else:
                    dep_filename = mod_id_to_filename.get(dep_id)
                    if not dep_filename or dep_filename not in all_mods_info:
                        continue
                    
                    dep_info = all_mods_info[dep_filename]
                    if dep_info['final_classification'] in ["雙端", "API / 函式庫"]:
                        info['final_classification'] = "雙端"
                        info['correction_reason'] = f"它依賴了一個雙端/API Mod '{dep_id}'"
                        info['was_corrected'] = True
                        corrections_made += 1
                        correction_made_for_this_mod = True
                
                if correction_made_for_this_mod:
                    break
    
    print(f"[階段 2] 完成，共進行 {corrections_made} 次校正。\n")

    # --- 階段 3: 歸檔檔案 (如果需要) ---
    if copy_output_dir:
        print("[階段 3] 正在歸檔 Mod 檔案...")
        copied_files = 0
        for filename, info in all_mods_info.items():
            classification = info['final_classification']
            target_folder_name = category_folders.get(classification, "5_Errors")
            source_path = mods_dir / filename
            dest_dir = copy_output_dir / target_folder_name
            
            try:
                shutil.copy2(source_path, dest_dir)
                copied_files += 1
            except Exception as e:
                print(f"    [錯誤] 無法複製檔案 {filename}: {e}")
        print(f"[階段 3] 完成，共歸檔 {copied_files} 個檔案。\n")

    # --- 寫入日誌檔案 ---
    try:
        write_log_file(output_log_path, all_mods_info, mods_dir)
        print("=" * 80)
        print(f"[*] 分析完成！詳細報告已成功寫入以下檔案：")
        print(f"    {output_log_path.resolve()}")
        print("=" * 80)
    except Exception as e:
        print(f"\n錯誤：無法寫入日誌檔案至 '{output_log_path}'. 請檢查權限或路徑。")
        print(f"錯誤詳情: {e}")

if __name__ == "__main__":
    main()