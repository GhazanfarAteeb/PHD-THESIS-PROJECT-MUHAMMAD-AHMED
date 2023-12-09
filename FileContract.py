import hashlib
import os

import hexbytes
import solcx
from eth_hash.backends.pycryptodome import keccak256
from solcx import set_solc_version, compile_source
from werkzeug.utils import secure_filename


class FileContract:
    def __init__(self):
        self.__contract_code = None
        self.__compiled_contract = None
        self.__interface = None
        self.__bin = None
        self.__abi = None
        self.__contract_compiled = False

    def compile_contract(self):
        solcx.install_solc('0.8.0')
        set_solc_version("0.8.0")

        with open("contracts/FileUpload.sol", "r") as contract_file:
            self.__contract_code = contract_file.read()
            self.__compiled_contract = compile_source(self.__contract_code)
            self.__interface = self.__compiled_contract['<stdin>:FileUpload']
            self.__bin = self.__interface['bin']
            self.__abi = self.__interface['abi']
            self.__contract_compiled = True

    def upload_file_simple(self, uploaded_file, w3, record, upload_folder):
        if not self.__contract_compiled:
            self.compile_contract()
        filename = secure_filename(uploaded_file.filename)
        receipt = self.__create_block_transaction(uploaded_file=uploaded_file, w3=w3, record=record,
                                                  upload_folder=upload_folder, filename=filename)
        with open(os.path.join(upload_folder, filename), "rb") as file:
            file_bytes = file.read()
            file_upload_contract_2 = w3.eth.contract(address=receipt['contractAddress'], abi=self.__abi)
            details = file_upload_contract_2.functions.uploadFileSimple(file_bytes).call()
            # print(file_bytes)
            return details, receipt, file_bytes

    def __create_block_transaction(self, uploaded_file, filename, w3, record, upload_folder):
        uploaded_file.save(os.path.join(upload_folder, filename))
        file_upload_gas_estimate = w3.eth.estimateGas({'data': self.__bin})
        deploy_file_upload_tx = {
            'from': record[4],
            'data': self.__bin,
            'gas': file_upload_gas_estimate,
            'gasPrice': w3.toWei('1', 'gwei'),
            'nonce': w3.eth.getTransactionCount(record[4])
        }
        file_upload_signed_tx = w3.eth.account.signTransaction(deploy_file_upload_tx, private_key=record[3])
        file_upload_tx_hash = w3.eth.sendRawTransaction(file_upload_signed_tx.rawTransaction)
        file_upload_tx_receipt = w3.eth.waitForTransactionReceipt(file_upload_tx_hash)
        return file_upload_tx_receipt

    def upload_file_via_shredding(self, uploaded_file, w3, record, upload_folder):
        if not self.__contract_compiled:
            self.compile_contract()
        filename = secure_filename(uploaded_file.filename)
        receipt = self.__create_block_transaction(uploaded_file=uploaded_file, filename=filename, w3=w3, record=record,
                                                  upload_folder=upload_folder)

        with open(os.path.join(upload_folder, filename), "rb") as file:
            file_bytes = file.read()
        chunk_size = 4096  # in bytes
        file_upload_contract_2 = w3.eth.contract(address=receipt['contractAddress'],
                                                 abi=self.__abi)
        details = file_upload_contract_2.functions.uploadFileViaShredding(file_bytes, chunk_size).call()
        return details, receipt

    def upload_file_with_HVT(self, uploaded_file, w3, record, upload_folder):
        if not self.__contract_compiled:
            self.compile_contract()
        filename = secure_filename(uploaded_file.filename)
        receipt = self.__create_block_transaction(uploaded_file=uploaded_file, w3=w3, record=record,
                                                  upload_folder=upload_folder, filename=filename)
        with open(os.path.join(upload_folder, filename), "rb") as file:
            file_bytes = file.read()
            file_upload_contract = w3.eth.contract(address=receipt['contractAddress'], abi=self.__abi)
            details = file_upload_contract.functions.uploadFileWithHVT(
                file_bytes,
                self.__compute_HVT_leaves(file_bytes)
            ).call()

        return details, receipt

    def upload_file_via_shredding_and_hvt(self, uploaded_file, w3, record, upload_folder):
        if not self.__contract_compiled:
            self.compile_contract()
        filename = secure_filename(uploaded_file.filename)
        receipt = self.__create_block_transaction(uploaded_file=uploaded_file, w3=w3, record=record,
                                                  upload_folder=upload_folder, filename=filename)

        with open(os.path.join(upload_folder, filename), "rb") as file:
            file_bytes = file.read()
            leaves = self.__compute_HVT_leaves(file_bytes)

            HVT_leaves = [bytes(leaf) for leaf in leaves]
            file_upload_contract = w3.eth.contract(address=receipt['contractAddress'], abi=self.__abi)
            chunk_size = 1024
            details = file_upload_contract.functions.uploadFileViaHvtAndShredding(file_bytes, HVT_leaves,
                                                                                  chunk_size).call()
        return details, receipt

    def __compute_HVT_leaves(self, file_bytes):
        if not self.__contract_compiled:
            self.compile_contract()
        chunk_size = 32
        num_leaves = (len(file_bytes) + chunk_size - 1) // chunk_size
        leaves = []

        for i in range(num_leaves):
            start_index = i * chunk_size
            end_index = min(start_index + chunk_size, len(file_bytes))
            chunk = file_bytes[start_index:end_index]
            leaf = hashlib.sha3_256(chunk).digest()
            leaves.append(leaf)

        return leaves

    def check_file(self, w3, record):
        if not self.__contract_compiled:
            self.compile_contract()
        contract = w3.eth.contract(address=record[3], abi=self.__abi)
        # file_bytes = b'\x00' * 32  # Adjust the conversion as per your file format
        # file_bytes = file_bytes[:len(record[4])] + record[4]

        # Call the checkFile function with the file bytes
        stored_hash = contract.functions.checkFile(record[4]).transact({'from': record[12]})
        print(stored_hash)
        return stored_hash
