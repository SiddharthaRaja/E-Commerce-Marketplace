import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
import time
import threading
import hashlib
import json
import random

class ZeroKnowledgeProof:
    def __init__(self, secret_password):
        self.secret_password = secret_password
        self.g = 7  # Random base (public parameter)
        self.p = 23  # Random prime (public parameter)

    def prove_knowledge(self):
        random_secret = random.randint(1, self.p - 2)
        commitment = pow(self.g, random_secret, self.p)
        challenge = random.randint(0, 1)

        if challenge == 0:
            response = (random_secret, commitment)
        else:
            response_value = (random_secret + 1) % (self.p - 1)
            response = (response_value, commitment)

        return challenge, response

    def verify_proof(self, challenge, response, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if hashed_password != self.secret_password:
            return False

        response_value, commitment = response
        if challenge == 0:
            return pow(self.g, response_value, self.p) == commitment
        else:
            lhs = pow(self.g, response_value, self.p)
            rhs = (commitment * pow(self.g, 1, self.p)) % self.p
            return lhs == rhs


class Order:
    def __init__(self, customer, product, quantity, amount):
        self.customer = customer
        self.product = product
        self.quantity = quantity
        self.amount = amount
        self.timestamp = time.time()

    def __str__(self):
        return f"Order by {self.customer} - Product: {self.product}, Quantity: {self.quantity}, Amount: {self.amount}"


class Block:
    def __init__(self, index, previous_hash, timestamp, orders, proof=0):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.orders = orders
        self.proof = proof
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_content = f"{self.index}{self.previous_hash}{self.timestamp}{json.dumps([o.__dict__ for o in self.orders])}{self.proof}"
        return hashlib.sha256(block_content.encode()).hexdigest()

    def __str__(self):
        orders_str = "\n    ".join(str(order) for order in self.orders)
        return f"Block #{self.index}:\n  Timestamp: {self.timestamp}\n  Previous Hash: {self.previous_hash}\n  Hash: {self.hash}\n  Orders:\n    {orders_str}"


class Blockchain:
    def __init__(self, difficulty=2):
        self.chain = [self.create_genesis_block()]
        self.difficulty = difficulty
        self.pending_orders = []
        self.nodes = []
        self.passwords = {}
        self.balances = {}
        self.data_catalog = {}

    def create_genesis_block(self):
        return Block(0, "0", time.time(), [])

    def get_latest_block(self):
        return self.chain[-1]

    def createBlock(self, orders):
        new_block = Block(len(self.chain), self.get_latest_block().hash, time.time(), orders)
        return new_block

    def verifyTransaction(self, order, password):
        if order.customer and order.product and order.quantity > 0 and order.amount > 0:
            hashed_password = self.passwords.get(order.customer, None)
            if not hashed_password:
                return False

            zk_proof = ZeroKnowledgeProof(hashed_password)
            challenge, response = zk_proof.prove_knowledge()
            if zk_proof.verify_proof(challenge, response, password):
                return True
        return False

    def add_order(self, order, password):
        if self.verifyTransaction(order, password):
            if order.product not in self.balances:
                self.balances[order.product] = 0
            self.balances[order.product] += order.amount
            self.pending_orders.append(order)
        else:
            raise ValueError("Order verification failed.")

    def mineBlock(self):
        if not self.pending_orders:
            messagebox.showwarning("No Orders", "There are no pending orders to mine.")
            return

        new_block = self.createBlock(self.pending_orders)
        difficulty = self.difficulty
        while new_block.hash[:difficulty] != "0" * difficulty:
            new_block.proof += 1
            new_block.hash = new_block.calculate_hash()

        self.chain.append(new_block)
        self.distribute_to_nodes(new_block)
        self.pending_orders = []
        messagebox.showinfo("Mining Complete", "New block added to the chain.")

    def distribute_to_nodes(self, block):
        for node in self.nodes:
            node.receive_block(block)
        print(f"Block distributed to {len(self.nodes)} nodes.")

    def add_node(self, node):
        self.nodes.append(node)
        print(f"Node {node.node_id} added to the network.")

    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash() or current_block.previous_hash != previous_block.hash:
                return False
        return True

    def set_user_password(self, user_id, password):
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.passwords[user_id] = hashed_password
        messagebox.showinfo("Success", f"Password set for user {user_id}.")

    def get_required_amount(self, product, quantity):
        if product in self.data_catalog:
            return self.data_catalog[product] * quantity
        return 0

    def add_data_product(self, product_name, price):
        self.data_catalog[product_name] = price
        messagebox.showinfo("Success", f"Added {product_name} to the data catalog for {price}.")

    def list_data_products(self):
        products_text = "Available Data Products:\n"
        for product, price in self.data_catalog.items():
            products_text += f"- {product}: {price}\n"
        return products_text

    def viewUser(self, user_id):
        transactions_text = f"\nTransactions for {user_id}:\n"
        for block in self.chain:
            for order in block.orders:
                if order.customer == user_id:
                    transactions_text += f" - Ordered {order.quantity} of {order.product} for {order.amount} at {time.ctime(order.timestamp)}\n"
        return transactions_text

    def display_chain(self):
        chain_text = "Blockchain:\n"
        for block in self.chain:
            chain_text += str(block) + "\n"
        return chain_text


class Node:
    def __init__(self, node_id):
        self.node_id = node_id
        self.local_chain = []

    def receive_block(self, block):
        self.local_chain.append(block)
        print(f"Node {self.node_id} received block {block.index} with hash {block.hash}")

    def is_local_chain_valid(self):
        for i in range(1, len(self.local_chain)):
            current_block = self.local_chain[i]
            previous_block = self.local_chain[i - 1]
            if current_block.hash != current_block.calculate_hash() or current_block.previous_hash != previous_block.hash:
                return False
        return True


class BlockchainApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("E-commerce Blockchain Marketplace")
        self.geometry("800x600")

        self.blockchain = Blockchain(difficulty=3)
        self.node1 = Node("Node1")
        self.node2 = Node("Node2")
        self.blockchain.add_node(self.node1)
        self.blockchain.add_node(self.node2)

        self.user_id_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.customer_var = tk.StringVar()
        self.product_var = tk.StringVar()
        self.quantity_var = tk.IntVar(value=1)
        self.add_order_password_var = tk.StringVar()

        self.setup_menu()
        self.setup_ui()

        self.blockchain.add_data_product("Laptop", 999.99)
        self.blockchain.add_data_product("Smartphone", 599.99)
        self.blockchain.add_data_product("Tablet", 299.99)

    def setup_menu(self):
        menu_bar = tk.Menu(self)
        self.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Set User Password", command=self.set_user_password)
        file_menu.add_command(label="Add Order", command=self.add_order)
        file_menu.add_command(label="Mine Pending Orders", command=self.mine_block)
        file_menu.add_command(label="View Blockchain", command=self.view_blockchain)
        file_menu.add_command(label="Perform Zero-Knowledge Proof", command=self.perform_zero_knowledge_proof)
        file_menu.add_command(label="Manage Data Products", command=self.manage_data_products)
        file_menu.add_command(label="View User Transactions", command=self.view_user_transactions)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

    def setup_ui(self):
        self.main_frame = tk.Frame(self, padx=20, pady=20)
        self.main_frame.pack(fill="both", expand=True)

        self.instructions = tk.Label(self.main_frame, text="Select an option from the menu to get started.", font=("Arial", 14))
        self.instructions.pack(pady=30)

    def manage_data_products(self):
        dialog = tk.Toplevel(self)
        dialog.title("Manage Data Products")
        dialog.geometry("400x300")

        tk.Label(dialog, text="Add New Product", font=("Arial", 12)).pack(pady=10)

        frame = tk.Frame(dialog)
        frame.pack(pady=10)

        tk.Label(frame, text="Product Name:").grid(row=0, column=0, padx=5, pady=5)
        name_entry = tk.Entry(frame)
        name_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Price:").grid(row=1, column=0, padx=5, pady=5)
        price_entry = tk.Entry(frame)
        price_entry.grid(row=1, column=1, padx=5, pady=5)

        def add_product():
            name = name_entry.get()
            try:
                price = float(price_entry.get())
                if name and price > 0:
                    self.blockchain.add_data_product(name, price)
                    show_products()
                else:
                    messagebox.showwarning("Input Error", "Please enter valid product details.")
            except ValueError:
                messagebox.showwarning("Input Error", "Please enter a valid price.")

        tk.Button(frame, text="Add Product", command=add_product).grid(row=2, column=0, columnspan=2, pady=10)

        products_frame = tk.Frame(dialog)
        products_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        products_text = tk.Text(products_frame, height=8, width=40)
        products_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(products_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        products_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=products_text.yview)

        def show_products():
            products_text.delete(1.0, tk.END)
            products_text.insert(tk.END, self.blockchain.list_data_products())

        show_products()

    def view_blockchain(self):
        dialog = tk.Toplevel(self)
        dialog.title("Blockchain View")
        dialog.geometry("600x400")

        text = tk.Text(dialog, wrap=tk.WORD, padx=10, pady=10)
        text.pack(fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(dialog, command=text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text.config(yscrollcommand=scrollbar.set)

        text.insert("1.0", self.blockchain.display_chain())
        text.config(state=tk.DISABLED)

    def perform_zero_knowledge_proof(self):
        dialog = tk.Toplevel(self)
        dialog.title("Zero-Knowledge Proof Verification")
        dialog.geometry("400x200")

        frame = tk.Frame(dialog)
        frame.pack(pady=10)

        tk.Label(frame, text="User ID:").grid(row=0, column=0, padx=5, pady=5)
        user_id_entry = tk.Entry(frame)
        user_id_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        password_entry = tk.Entry(frame, show="*")
        password_entry.grid(row=1, column=1, padx=5, pady=5)

        def verify():
            user_id = user_id_entry.get()
            password = password_entry.get()
            zk_proof = ZeroKnowledgeProof(self.blockchain.passwords.get(user_id, None))
            challenge, response = zk_proof.prove_knowledge()
            if zk_proof.verify_proof(challenge, response, password):
                messagebox.showinfo("Success", "Verification successful!")
            else:
                messagebox.showerror("Failed", "Verification failed.")

        tk.Button(dialog, text="Verify", command=verify).pack(pady=10)

    def mine_block(self):
        print("Mining pending orders...")
        self.blockchain.mineBlock()

    def set_user_password(self):
        dialog = tk.Toplevel(self)
        dialog.title("Set User Password")
        dialog.geometry("400x200")

        tk.Label(dialog, text="Set User Password", font=("Arial", 12)).pack(pady=10)

        frame = tk.Frame(dialog)
        frame.pack(pady=10)

        tk.Label(frame, text="User ID:").grid(row=0, column=0, padx=5, pady=5)
        user_id_entry = tk.Entry(frame)
        user_id_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        password_entry = tk.Entry(frame, show="*")
        password_entry.grid(row=1, column=1, padx=5, pady=5)

        def set_password():
            user_id = user_id_entry.get()
            password = password_entry.get()
            self.blockchain.set_user_password(user_id, password)
            user_id_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)

        tk.Button(dialog, text="Set Password", command=set_password).pack(pady=10)

    def add_order(self):
        dialog = tk.Toplevel(self)
        dialog.title("Add Order")
        dialog.geometry("800x800")

        tk.Label(dialog, text="Add New Order", font=("Arial", 12)).pack(pady=10)

        frame = tk.Frame(dialog)
        frame.pack(pady=10)

        tk.Label(frame, text="Customer:").grid(row=0, column=0, padx=5, pady=5)
        customer_entry = tk.Entry(frame, textvariable=self.customer_var)
        customer_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(frame, text="Product:").grid(row=1, column=0, padx=5, pady=5)
        product_entry = tk.Entry(frame, textvariable=self.product_var)
        product_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Label(frame, text="Quantity:").grid(row=2, column=0, padx=5, pady=5)
        quantity_entry = tk.Spinbox(frame, from_=1, to=100, textvariable=self.quantity_var)
        quantity_entry.grid(row=2, column=1, padx=5, pady=5)

        tk.Label(frame, text="Password:").grid(row=3, column=0, padx=5, pady=5)
        password_entry = tk.Entry(frame, show="*", textvariable=self.add_order_password_var)
        password_entry.grid(row=3, column=1, padx=5, pady=5)

        def place_order():
            customer = self.customer_var.get()
            product = self.product_var.get()
            quantity = self.quantity_var.get()
            password = self.add_order_password_var.get()
            amount = self.blockchain.get_required_amount(product, quantity)
            if amount > 0:
                order = Order(customer, product, quantity, amount)
                try:
                    self.blockchain.add_order(order, password)
                    messagebox.showinfo("Success", "Order placed successfully.")
                    self.customer_var.set("")
                    self.product_var.set("")
                    self.quantity_var.set(1)
                    self.add_order_password_var.set("")
                except ValueError as e:
                    messagebox.showerror("Error", str(e))
            else:
                messagebox.showwarning("Invalid Order", "Product not found or invalid quantity.")

        tk.Button(dialog, text="Place Order", command=place_order).pack(pady=10)

    def view_user_transactions(self):
        dialog = tk.Toplevel(self)
        dialog.title("User Transactions")
        dialog.geometry("800x800")

        tk.Label(dialog, text="View User Transactions", font=("Arial", 12)).pack(pady=10)

        frame = tk.Frame(dialog)
        frame.pack(pady=10)

        tk.Label(frame, text="User ID:").grid(row=0, column=0, padx=5, pady=5)
        user_id_entry = tk.Entry(frame)
        user_id_entry.grid(row=0, column=1, padx=5, pady=5)

        def view_transactions():
            user_id = user_id_entry.get()
            transactions_text = self.blockchain.viewUser(user_id)
            messagebox.showinfo("User Transactions", transactions_text)

        tk.Button(frame, text="View Transactions", command=view_transactions).grid(row=1, column=0, columnspan=2, pady=10)


if __name__ == "__main__":
    app = BlockchainApp()
    app.mainloop()
