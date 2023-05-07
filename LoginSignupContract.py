import solcx
from solcx import set_solc_version, compile_source


class LoginSignupContract:
    def __init__(self):
        self.__contract_code = None
        self.__compiled_contract = None
        self.__interface = None
        self.__bin = None
        self.__abi = None
        self.__compile_contract()

    def __compile_contract(self):
        solcx.install_solc('0.8.0')
        set_solc_version("0.8.0")
        with open("contracts/LoginSignup.sol", "r") as contract_file:
            self.__contract_code = contract_file.read()
            self.__compiled_contract = compile_source(self.__contract_code)
            self.__interface = self.__compiled_contract['<stdin>:LoginSignup']
            self.__bin = self.__interface['bin']
            self.__abi = self.__interface['abi']

    def register(self, w3, account_address, private_key, username, password):
        login_signup_deploy_tx = {
            'from': account_address,
            'data': self.__bin,
            'gas': w3.eth.estimateGas({'data': self.__bin}),  # estimating the gas
            'gasPrice': w3.toWei('1', 'gwei'),
            'nonce': w3.eth.getTransactionCount(account_address)
        }
        # signing the transaction
        login_signup_signed_tx = w3.eth.account.signTransaction(login_signup_deploy_tx,
                                                                private_key=private_key)
        # sending the raw transaction
        login_signup_tx_hash = w3.eth.sendRawTransaction(login_signup_signed_tx.rawTransaction)
        # waiting for the receipt of the transaction
        login_signup_tx_receipt = w3.eth.waitForTransactionReceipt(login_signup_tx_hash)

        # using the compiled contract's abi and the created contract address the contract call will run
        # the signup method to mine the user signup block
        login_signup_contract_2 = w3.eth.contract(address=login_signup_tx_receipt['contractAddress'],
                                                  abi=self.__abi)

        # creating the transaction for signup function of the smart contract
        login_signup_tx = login_signup_contract_2.functions.signup(username, password) \
            .buildTransaction({
                'gas': 100000,
                'gasPrice': w3.toWei('0.00000001', 'ether'),
                'nonce': w3.eth.getTransactionCount(account_address)
            })
        # signing up the transaction
        login_signup_signed_tx = w3.eth.account.signTransaction(login_signup_tx,
                                                                private_key=private_key)
        # sending the transaction
        login_signup_tx_hash = w3.eth.sendRawTransaction(login_signup_signed_tx.rawTransaction)
        # waiting for the receipt
        login_signup_tx_receipt_2 = w3.eth.waitForTransactionReceipt(login_signup_tx_hash)

        return login_signup_tx_receipt_2

    def login(self, record, w3):
        login_signup_contract_address = record[4]
        login_signup_contract_2 = w3.eth.contract(address=login_signup_contract_address,
                                                  abi=self.__abi)

        # building the transaction for the login process
        login_signup_tx = login_signup_contract_2.functions.login(record[1], record[2]).buildTransaction({
            'gas': 100000,
            'gasPrice': w3.toWei('0.00000001', 'ether'),
            'nonce': w3.eth.getTransactionCount(record[4])
        })
        # signing the blockchain transaction
        login_signup_signed_tx = w3.eth.account.signTransaction(login_signup_tx, private_key=record[3])
        # sending the blockchain transaction
        login_signup_tx_hash = w3.eth.sendRawTransaction(login_signup_signed_tx.rawTransaction)
        # wait for getting the transaction receipt
        login_signup_tx_receipt = w3.eth.waitForTransactionReceipt(login_signup_tx_hash)

        return login_signup_tx_receipt

