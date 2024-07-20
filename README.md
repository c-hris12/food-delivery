# Food Ordering and Delivery System

## Description

This project is a decentralized food ordering and delivery system built on the Internet Computer (IC). It allows customers to browse menus from various restaurants, place orders, and have them delivered by delivery personnel. Restaurant owners can manage their restaurants and menu items, while delivery personnel can accept and deliver orders.

## Features

### User Registration and Authentication
- Users can register as customers, restaurant owners, or delivery personnel.
- Authentication ensures secure access to user-specific functionalities.

### Restaurant Management
- Restaurant owners can create and manage their restaurants.
- Restaurant owners can add and manage menu items for their restaurants.

### Menu Management
- Menu items include details such as name, description, price, and quantity.
- Menu items are associated with specific restaurants.

### Order Placement
- Customers can browse restaurant menus and place orders.
- Orders include a list of menu items and the total bill amount.

### Order Processing
- Orders have statuses such as "pending", "preparing", and "delivered".
- Delivery personnel can accept orders and update their delivery status.

### Delivery Management
- Delivery personnel can accept assigned deliveries.
- Delivery statuses include "assigned", "in transit", and "delivered".

### Role-based Permissions
- Restaurant owners can only manage their own restaurants and menu items.
- Delivery personnel can only manage deliveries assigned to them.
- Customers can only place orders and view their order history.

### Data Persistence
- User, restaurant, menu item, order, and delivery data are stored securely using the IC's stable storage mechanisms.

### Secure and Decentralized
- The system leverages the decentralized nature of the Internet Computer for secure and tamper-proof operations.





## Requirements
* rustc 1.64 or higher
```bash
$ curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
$ source "$HOME/.cargo/env"
```
* rust wasm32-unknown-unknown target
```bash
$ rustup target add wasm32-unknown-unknown
```
* candid-extractor
```bash
$ cargo install candid-extractor
```
* install `dfx`
```bash
$ DFX_VERSION=0.15.0 sh -ci "$(curl -fsSL https://sdk.dfinity.org/install.sh)"
$ echo 'export PATH="$PATH:$HOME/bin"' >> "$HOME/.bashrc"
$ source ~/.bashrc
$ dfx start --background
```

If you want to start working on your project right away, you might want to try the following commands:

```bash
$ cd icp_rust_boilerplate/
$ dfx help
$ dfx canister --help
```

## Update dependencies

update the `dependencies` block in `/src/{canister_name}/Cargo.toml`:
```
[dependencies]
candid = "0.9.9"
ic-cdk = "0.11.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1.0"
ic-stable-structures = { git = "https://github.com/lwshang/stable-structures.git", branch = "lwshang/update_cdk"}
```

## did autogenerate

Add this script to the root directory of the project:
```
https://github.com/buildwithjuno/juno/blob/main/scripts/did.sh
```

Update line 16 with the name of your canister:
```
https://github.com/buildwithjuno/juno/blob/main/scripts/did.sh#L16
```

After this run this script to generate Candid.
Important note!

You should run this script each time you modify/add/remove exported functions of the canister.
Otherwise, you'll have to modify the candid file manually.

Also, you can add package json with this content:
```
{
    "scripts": {
        "generate": "./did.sh && dfx generate",
        "gen-deploy": "./did.sh && dfx generate && dfx deploy -y"
      }
}
```

and use commands `npm run generate` to generate candid or `npm run gen-deploy` to generate candid and to deploy a canister.

## Running the project locally

If you want to test your project locally, you can use the following commands:

```bash
# Starts the replica, running in the background
$ dfx start --background

# Deploys your canisters to the replica and generates your candid interface
$ dfx deploy
```