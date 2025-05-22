import hashlib
import magic

import os
import shutil

import json

from karton.core import Task, Resource
import zipfile
from zipfile import ZipFile

class GetFileTypes():
    """
    Gets file types.
    """

    def get_file_type(self, file_path):
        mime = magic.Magic(mime=True)
        file_mime = mime.from_file(file_path)

        if file_mime == "application/octet-stream":
            try:
                with open(file_path, 'rb') as file:
                    file_header = file.read(8)
                    if file_header.startswith(b'dex\n'):
                        file_type = "dex"
            except FileNotFoundError:
                print(f"  [-] The file at {file_path} was not found.")
                file_type = "error"
                return file_type
        elif file_mime == "application/zip":
            try:
                with ZipFile(file_path, 'r') as zip_file:
                    if "AndroidManifest.xml" in zip_file.namelist() and any(name.endswith('.dex') for name in zip_file.namelist()):
                        file_type = "apk"
            except zipfile.BadZipFile:
                file_type = "error"
                return file_type
        else:
            file_type = magic.from_file(file_path)

        return file_type

    def get_file_hash(self, file_path):
        try:
            hash_func = hashlib.new("sha256")
            with open(file_path, 'rb') as file:
                while chunk := file.read(8192):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except FileNotFoundError:
            print(f"  [-] The file at {file_path} was not found.")

    def read_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                file_content = file.read()
                return file_content
        except FileNotFoundError:
            print(f"  [-] The file at {file_path} was not found.")

    def process(self, file_path):
        print("[GET FILE TYPE] Getting file type...")
        file_type = self.get_file_type(file_path)
        if "error" in file_type:
            print("  [-] Error in getting file type")
        else:
            print(f"  [-] Successfully obtained file type: {file_type}")
        
        sha256sum = self.get_file_hash(file_path)
        
        # Create new folder
        folder_name = sha256sum
        folder_path = os.path.join(os.getcwd(), folder_name)
        os.makedirs(folder_path, exist_ok=True)
        print(f"[GET FILE TYPE] Creating dir {folder_path}...")

        # Copy file to new folder
        shutil.copy(file_path, folder_path)

        file_content = self.read_file(file_path)

        if file_content is not None:
            task = Task(
                {
                    "type": "sample",
                    "stage": "analyzed",
                    "kind": f"{file_type}",
                    "out": "get-file-type",
                }, 
                payload={
                    "sample": Resource(name=f"{sha256sum}", content=file_content),
                    "folder_path": folder_path,
                    "root_parent_path": file_path,
                    "sha256": sha256sum,
                }
            )
        else:
            print("[GET FILE TYPE] Empty file content.")

        json_task = json.loads(str(task))
        return file_type, json_task