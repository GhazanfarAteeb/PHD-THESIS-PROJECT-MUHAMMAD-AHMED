import solcx
from solcx import set_solc_version, compile_source


class DataStorage:
    def __init__(self):
        self.__contract_code = None
        self.__compiled_contract = None
        self.__interface = None
        self.__bin = None
        self.__abi = None
        self.__contract_compiled = False

    def __compile_contract(self):
        solcx.install_solc('0.8.0')
        set_solc_version("0.8.0")

        with open("contracts/DataStorage.sol", "r") as contract_file:
            self.__contract_code = contract_file.read()
        self.__compiled_contract = compile_source(self.__contract_code)
        self.__interface = self.__compiled_contract['<stdin>:DataStorage']
        self.__abi = self.__interface['abi']
        self.__bin = self.__interface['bin']
        self.__contract_compiled = True

    def create_block(self, w3, record):
        if not self.__contract_compiled:
            self.__compile_contract()
        estimated_gas = w3.eth.estimateGas({'data': self.__bin})
        # Prepare and sign transaction for contract deployment
        deploy_data_upload_tx = {
            'from': record[4],
            'data': self.__bin,
            'gas': estimated_gas,
            'gasPrice': w3.toWei('1', 'gwei'),
            'nonce': w3.eth.getTransactionCount(record[4])
        }
        data_upload_signed_tx = w3.eth.account.signTransaction(deploy_data_upload_tx, private_key=record[3])

        # Send the signed transaction for contract deployment
        data_upload_tx_hash = w3.eth.sendRawTransaction(data_upload_signed_tx.rawTransaction)

        # Wait for the transaction receipt
        data_upload_tx_receipt = w3.eth.waitForTransactionReceipt(data_upload_tx_hash)
        return data_upload_tx_receipt

    def store_bytes(self, w3, contract_address, tx_from, signature):
        if not self.__contract_compiled:
            self.__compile_contract()

        # Create a contract instance based on the deployed contract address and ABI
        data_upload_contract_2 = w3.eth.contract(address=contract_address,
                                                 abi=self.__abi)

        # Call the contract function to store the file chunk signature
        data_upload_contract_2.functions.storeBytes(signature).transact({'from': tx_from})

    def retrieve_bytes(self, w3, record, signature, contract_address):
        if not self.__contract_compiled:
            self.__compile_contract()
        data_upload_contract_2 = w3.eth.contract(address=contract_address,
                                                 abi=self.__abi)
        details_2 = data_upload_contract_2.functions.getBytes(signature).call({'from': record[4]})
        return details_2

    def verify(self, w3, contract_address, signature, record, file_bytes_array, index, vk):
        if not self.__contract_compiled:
            self.__compile_contract()
        data_upload_contract_2 = w3.eth.contract(address=contract_address,
                                                 abi=self.__abi)
        details_2 = data_upload_contract_2.functions.getBytes(signature).call({'from': record[4]})
        print(f'signature ==>{signature}')
        print(f'blockchain returned ==>{details_2}')
        print("\n\n\n")
        result = vk.verify(signature=details_2, data=file_bytes_array[index])
        return result
