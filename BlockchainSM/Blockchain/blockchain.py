from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from time import time
from collections import OrderedDict
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from uuid import uuid4
from urllib.parse import urlparse
import binascii
import json
import hashlib
import requests

# Constants for mining settings
Mining_Sender = "The Blockchain"
Mining_Reward = 1  # reward 1 coin to miner
Mining_Difficulty = 2  # default difficulty


class Blockchain:

    def __init__(self):
        # List of transactions
        self.transactions = []
        # List of blocks in the chain
        self.chain = []
        # List of nodes
        self.nodes = set()
        # Unique node id
        self.node_id = str(uuid4()).replace('', '')
        # Genesis block
        self.create_block(0, "00")


    ''' 
        ______________________
        CREATE A BLOCK METHOD
    '''
    def create_block(self, nonce, previous_hash):
        # Add a block of transactions to the chain
        block = {"block_number": len(self.chain) + 1,
                 "timestamp": time(),
                 "transactions": self.transactions,
                 "nonce": nonce,
                 "previous_hash": previous_hash
                 }
        # Add transactions to the block
        self.transactions = []
        self.chain.append(block)
        return block


    ''' 
        ______________________
        HASH THE BLOCK METHOD
        creates a SHA-256 hash of a block
    '''
    @staticmethod
    def hash(block):
        # ensure that the dictionary is ordered, otherwise we'll get inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode('utf8')  # convert block into a string
        h = hashlib.new('sha256')
        h.update(block_string)
        return h.hexdigest()  # returns the hexadecimal SHA-256 hash of the block string


    ''' 
        _____________________________
        SIGNATURE VERIFICATION METHOD
        maintaining the integrity of transactions in the blockchain
        !Part of Submit Transaction method
    '''
    def verify_transaction_signature(self, sender_public_key, signature, transaction):
        # imports the sender’s public key using methods from PyCrypto library
        public_key = RSA.importKey(binascii.unhexlify(sender_public_key))
        verifier = PKCS1_v1_5.new(public_key)
        # hashes the string representation of the transaction details
        # the string is encoded in UTF-8 before hashing
        h = SHA.new(str(transaction).encode('utf8'))
        try:
            # verify the signature of the hash
            # convert the hexadecimal string of the signature back into binary
            verifier.verify(h, binascii.unhexlify(signature))
            return True
        except ValueError:
            return False


    '''
        ________________________
        PROOF VALIDATING METHOD
        validates the proof of work for a block
        !Part of Proof-of-Work method
    '''
    @staticmethod
    def valid_proof(transactions, last_hash, nonce, difficulty=Mining_Difficulty):
        # concatenates and encodes transaction data, last hash, and nonce
        guess = (str(transactions) + str(last_hash) + str(nonce)).encode('utf8')
        # computes the SHA-256 hash of the guess and updates it with the encoded string to generate a hash
        h = hashlib.sha256()
        h.update(guess)
        guess_hash = h.hexdigest()
        # checks if the hash meets the difficulty requirement (number of leading zeros)
        return guess_hash[:difficulty] == '0' * difficulty

    '''
        ______________________
        PROOF OF WORK METHOD
        finds a valid nonce for the new block
        !Part of mining method
    '''
    def proof_of_work(self):
        last_block = self.chain[-1]  # gets the last block from the chain
        last_hash = self.hash(last_block)  # hashes the last block
        nonce = 0  # number used once and incremented in each iteration of the loop
        # invokes PROOF VALIDATING METHOD
        # continuously increments nonce until a valid hash is found
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1
        return nonce  # returns the valid nonce that makes the block's hash meet the difficulty criteria


    ''' 
        ______________________
        REGISTER NODE METHOD
        Add new nodes to the blockchain 
        !Part of Retrieve Miner Nodes method
    '''
    def register_node(self, node_url):
        # Adds a new node to the set of nodes after validating the URL
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts a URL without scheme like 192.168.0.0
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    ''' 
        ___________________
        VALID CHAIN METHOD
        Needs to validate the chain because each node maintain its own blockchain
        This retrieves latest update from the other node
        The node with longest blockchain wins
        !Part of CONSENSUS PROTOCOL
        !Part of Resolve Conflict Between Nodes method
    '''
    def valid_chain(self, chain):
        # Get the first block in the chain
        last_block = chain[0]
        current_index = 1

        # Loop through the chain until the end
        while current_index < len(chain):
            block = chain[current_index]  # Get the block at the current index

            # Check if the previous hash in the current block matches the hash of the last block
            if block['previous_hash'] != self.hash(last_block):
                return False  # If they are not equal, the chain is not valid

            # Get the transactions from the current block (excluding the last transaction)
            transactions = block['transactions'][:-1]
            transaction_elements = ['sender_public_key', 'recipient_public_key', 'amount']
            # Extract transactions and checks the proof of work
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in
                            transactions]  # creates a list of ordered dictionaries for the transactions

            # Check if the proof of work for these transactions, previous_hash of the block, and nonce of the block is valid
            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], Mining_Difficulty):
                # If the proof is not valid, the chain is not valid
                return False

            # If the 'previous_hash' and the proof are both valid, set the last block to the current block
            last_block = block
            current_index += 1

        # If the loop completes without finding any invalid 'previous_hash' or proof, the chain is valid
        return True


    '''
        _____________________________________
        RESOLVE CONFLICT BETWEEN NODES METHOD
        ensures that all nodes in the network have the longest valid chain
        and blockchain on all nodes the same
        !CORE COMPONENT OF CONSENSUS PROTOCOL
    '''
    def resolve_conflicts(self):
        neighbours = self.nodes  # get the set of nodes in the network
        new_chain = None  # placeholder for a new, potentially longer chain

        # Get the length of the current chain
        max_length = len(self.chain)
        # Iterate over each node in the network
        for node in neighbours:
            # Send a GET request to the node's /chain endpoint to retrieve its version of the blockchain
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                # Get the length and the chain from the response
                length = response.json()['length']
                chain = response.json()['chain']
                # Checks if the node's chain is longer and valid
                # Invokes VALID CHAIN METHOD
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain  # updates the new_chain with the longer valid chain

        # If new_chain is not None means a longer and valid chain was found
        if new_chain:
            # Set the current chain to new_chain and return True
            self.chain = new_chain
            return True
        # If new_chain is None means no longer and valid chain was found
        return False


    ''' 
        __________________________
        SUBMIT TRANSACTION METHOD
        adds a transaction to the list of pending transactions if it's valid
        !Part of Create New Transaction method
    '''
    def submit_transaction(self, sender_public_key, recipient_public_key, signature, amount):
        transaction = OrderedDict({
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'amount': amount
        })
        # Reward the miner for mining a block
        if sender_public_key == Mining_Sender:
            self.transactions.append(transaction)
            return len(self.chain) + 1  # returns the index of the block that will hold this transaction
        else:
            # Invokes SIGNATURE VERIFICATION METHOD
            # For all other transactions, the signature is verified.
            signature_verification = self.verify_transaction_signature(sender_public_key,
                                                                       recipient_public_key,
                                                                       signature)
            if signature_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            # If the transaction is not valid / signature doesn't match, it's not added to the list
            else:
                return False


# Flask Application Setup
blockchain = Blockchain()  # Creates an instance of the Blockchain
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Enables CORS for all routes


@app.route("/")
def index():
    return render_template("./blockchain.html")


@app.route("/configure")
def configure():
    return render_template("./configure.html")


''' 
    _____________________________
    CREATE NEW TRANSACTION METHOD
    handles the creation of new transactions
    receives transaction data from the user request form
'''
@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form
    required = ['confirmation_sender_public_key', 'confirmation_recipient_public_key',
                'transaction_signature', 'confirmation_amount']
    # Checks if all required fields are present in the request
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Invoke SUBMIT TRANSACTION METHOD
    # submits the transaction for inclusion in the blockchain
    transaction_results = blockchain.submit_transaction(values['confirmation_sender_public_key'],
                                                        values['confirmation_recipient_public_key'],
                                                        values['transaction_signature'],
                                                        values['confirmation_amount'])

    # Checks if the transaction was successfully added
    if not transaction_results:
        response = {'message': 'Invalid transaction/signature'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to the block' + str(transaction_results)}
        return jsonify(response), 201


''' 
    ______________________
    GET TRANSACTION METHOD
    Handling the transaction from User Client to Miner Client
    Add the new transaction to UNMINED transaction table
'''
@app.route('/transactions/get', methods=['GET'])
def get_transaction():
    # add the transaction details from confirmation form to the unmined transaction table
    transactions = blockchain.transactions
    response = {'transactions': transactions}
    return jsonify(response), 200


''' 
    _____________________
    M I N I N G - METHOD
    Finding the nonce
    Solve cryptographic puzzle
'''
@app.route('/mine', methods=['GET'])
def mine():
    # Invokes PROOF OF WORK METHOD
    nonce = blockchain.proof_of_work()

    # Creates a reward transaction for the miner
    reward_message = 'Rewarded coin = ' + str(Mining_Reward)
    blockchain.submit_transaction(sender_public_key=Mining_Sender,
                                  recipient_public_key=blockchain.node_id,
                                  signature='',
                                  amount=reward_message)

    # Retrieves the last block and calculates its hash
    last_block = blockchain.chain[-1]
    previous_hash = blockchain.hash(last_block)
    # Creates a new block with the found nonce and the hash of the last block
    block = blockchain.create_block(nonce, previous_hash)
    # Prepares a response with the details of the newly mined block
    response = {
        'message': 'New block created',
        'block number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


''' 
    __________________________
    GET THE BLOCKCHAIN METHOD
    get the mined block 
    to add the block to the blockchain / mined transaction table
'''
@app.route('/chain', methods=['GET'])
def get_chain():
    response = {
        # The complete list of blocks in the blockchain
        'chain': blockchain.chain,
        # How many block currently have
        'length': len(blockchain.chain)
    }
    return jsonify(response), 200


''' 
    _____________________________
    RETRIEVES MINER NODES METHOD
    This resource is to add more miners to the network
    More miners = safer blockchain
    !both routes
'''
@app.route('/nodes/get', methods=['GET'])
def retrieve_nodes():
    # Retrieves the list of registered nodes in the network.
    nodes = list(blockchain.nodes)  # converts the set of nodes to a list
    response = {'nodes': nodes}
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def handle_nodes():
    # Handles the registration of new nodes to the network
    values = request.form
    nodes = values.get('nodes').replace('', '').split(',')  # extracts and splits the node URLs from the form data

    if nodes is None:
        return 'Error: Please supply a valid list of nodes', 400
    for node in nodes:
        # Invokes REGISTER NODE METHOD
        blockchain.register_node(node)
    response = {
        'message': 'Node have been added',
        'total_nodes': [node for node in blockchain.nodes]  # list of all registered nodes
    }
    return jsonify(response), 200


''' 
    __________________________
    CONSENSUS PROTOCOL METHOD
    achieves consensus in the network
    all nodes have the same and latest blockchain
'''
@app.route('/nodes/resolve', methods=['GET'])
def consensus_protocol():
    # Invokes RESOLVE CONFLICT BETWEEN NODES METHOD
    # resolve conflicts and update the chain
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'new_chain': blockchain.chain  # the updated chain
        }
    else:
        response = {
            'chain': blockchain.chain  # the current chain
        }
    return jsonify(response), 200


if __name__ == "__main__":
    # Command-line argument parsing for setting the port
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=1001, type=int, help="port to listen to")
    args = parser.parse_args()
    port = args.port

    # Starts the Flask application on the specified port
    app.run(host="127.0.0.1", port=port, debug=True)
