#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use regex::Regex;
use std::{borrow::Cow, cell::RefCell};

type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

// UserRole Enum
#[derive(
    candid::CandidType, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default, Debug,
)]
enum UserRole {
    #[default]
    Customer,
    RestaurantOwner,
    DeliveryPerson,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct User {
    id: u64,
    username: String,
    email: String,
    phone_number: String,
    role: UserRole,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Restaurant {
    id: u64,
    owner_id: u64,
    name: String,
    description: String,
    address: String,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct MenuItem {
    id: u64,
    restaurant_id: u64,
    name: String,
    description: String,
    price: f64,
    quantity_kg: u64,
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Order {
    id: u64,
    customer_id: u64,
    restaurant_id: u64,
    items: Vec<u64>, // MenuItem IDs
    total_bill: f64,
    status: String, // "pending", "preparing", "delivered"
    created_at: u64,
}

#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Delivery {
    id: u64,
    order_id: u64,
    delivery_person_id: u64,
    status: String, // "assigned", "in transit", "delivered"
    created_at: u64,
}

impl Storable for User {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for User {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Restaurant {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Restaurant {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for MenuItem {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for MenuItem {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Order {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Order {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

impl Storable for Delivery {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Delivery {
    const MAX_SIZE: u32 = 1024;
    const IS_FIXED_SIZE: bool = false;
}

thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static ID_COUNTER: RefCell<IdCell> = RefCell::new(
        IdCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0))), 0)
            .expect("Cannot create a counter")
    );

    static USER_STORAGE: RefCell<StableBTreeMap<u64, User, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));

    static RESTAURANT_STORAGE: RefCell<StableBTreeMap<u64, Restaurant, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
    ));

    static MENU_STORAGE: RefCell<StableBTreeMap<u64, MenuItem, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
    ));

    static ORDER_STORAGE: RefCell<StableBTreeMap<u64, Order, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))
    ));

    static DELIVERY_STORAGE: RefCell<StableBTreeMap<u64, Delivery, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5)))
    ));
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct UserPayload {
    username: String,
    email: String,
    phone_number: String,
    role: UserRole,
}

// AuthenticatedUserPayload is used to authenticate a user
#[derive(candid::CandidType, Deserialize, Serialize)]
struct AuthenticatedUserPayload {
    username: String,
    role: UserRole,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct RestaurantPayload {
    owner_id: u64,
    name: String,
    description: String,
    address: String,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct MenuItemPayload {
    restaurant_id: u64,
    name: String,
    description: String,
    price: f64,
    quantity_kg: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct OrderPayload {
    customer_id: u64,
    restaurant_id: u64,
    items: Vec<u64>,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
struct DeliveryPayload {
    order_id: u64,
    delivery_person_id: u64,
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Message {
    Success(String),
    Error(String),
    NotFound(String),
    InvalidPayload(String),
    UnAuthorized(String),
}

#[ic_cdk::update]
fn create_user(payload: UserPayload) -> Result<User, Message> {
    // Validate payload to ensure all fields are provided
    if payload.username.is_empty()
        || payload.email.is_empty()
        || payload.phone_number.is_empty()
        || payload.role == UserRole::default()
    {
        return Err(Message::InvalidPayload(
            "Ensure 'username', 'email', 'phone_number', and 'role' are provided.".to_string(),
        ));
    }

    // Validate the email address format
    let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
    if !email_regex.is_match(&payload.email) {
        return Err(Message::InvalidPayload("Invalid email address".to_string()));
    }

    // Ensure each email is unique
    let email_exists = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.email == payload.email)
    });
    if email_exists {
        return Err(Message::InvalidPayload("Email already exists".to_string()));
    }

    // Validate the phone number format
    let phone_regex = Regex::new(r"^\+?[0-9]{10,14}$").unwrap();
    if !phone_regex.is_match(&payload.phone_number) {
        return Err(Message::InvalidPayload("Invalid phone number".to_string()));
    }

    // Ensure the username is unique
    let username_exists = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.username == payload.username)
    });
    if username_exists {
        return Err(Message::InvalidPayload(
            "Username already exists".to_string(),
        ));
    }

    // Increment the ID counter and create a new user
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let user = User {
        id,
        username: payload.username,
        email: payload.email,
        phone_number: payload.phone_number,
        role: payload.role,
        created_at: current_time(),
    };

    // Insert the user into the storage and return the user
    USER_STORAGE.with(|storage| storage.borrow_mut().insert(id, user.clone()));
    Ok(user)
}

#[ic_cdk::query]
fn get_users() -> Result<Vec<User>, Message> {
    USER_STORAGE.with(|storage| {
        let users: Vec<User> = storage
            .borrow()
            .iter()
            .map(|(_, user)| user.clone())
            .collect();

        if users.is_empty() {
            Err(Message::NotFound("No users found".to_string()))
        } else {
            Ok(users)
        }
    })
}

fn authenticate_user(payload: AuthenticatedUserPayload) -> Result<User, Message> {
    USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, user)| user.username == payload.username && user.role == payload.role)
            .map(|(_, user)| user.clone())
            .ok_or(Message::UnAuthorized("Invalid credentials".to_string()))
    })
}

#[ic_cdk::update]
fn create_restaurant(
    payload: RestaurantPayload,
    user_payload: AuthenticatedUserPayload,
) -> Result<Restaurant, Message> {
    // Check if the user is a restaurant owner
    let user = authenticate_user(user_payload)?;
    if user.role != UserRole::RestaurantOwner {
        return Err(Message::UnAuthorized(
            "You do not have permission to create a restaurant".to_string(),
        ));
    }

    // Validate payload to ensure all fields are provided
    if payload.name.is_empty() || payload.description.is_empty() || payload.address.is_empty() {
        return Err(Message::InvalidPayload(
            "Ensure 'name', 'description', and 'address' are provided.".to_string(),
        ));
    }

    // Validate the owner ID
    if user.id != payload.owner_id {
        return Err(Message::UnAuthorized(
            "The restaurant owner with the provided id cannot be found".to_string(),
        ));
    }

    // Increment the ID counter and create a new restaurant
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let restaurant = Restaurant {
        id,
        owner_id: payload.owner_id,
        name: payload.name,
        description: payload.description,
        address: payload.address,
        created_at: current_time(),
    };

    // Insert the restaurant into the storage and return the restaurant
    RESTAURANT_STORAGE.with(|storage| storage.borrow_mut().insert(id, restaurant.clone()));
    Ok(restaurant)
}

#[ic_cdk::query]
fn get_restaurants() -> Result<Vec<Restaurant>, Message> {
    RESTAURANT_STORAGE.with(|storage| {
        let restaurants: Vec<Restaurant> = storage
            .borrow()
            .iter()
            .map(|(_, restaurant)| restaurant.clone())
            .collect();

        if restaurants.is_empty() {
            Err(Message::NotFound("No restaurants found".to_string()))
        } else {
            Ok(restaurants)
        }
    })
}

#[ic_cdk::update]
fn create_menu_item(
    payload: MenuItemPayload,
    user_payload: AuthenticatedUserPayload,
) -> Result<MenuItem, Message> {
    // Authenticate the user
    let user = authenticate_user(user_payload)?;

    // Ensure the user is a restaurant owner
    if user.role != UserRole::RestaurantOwner {
        return Err(Message::UnAuthorized(
            "You do not have permission to create a menu item.".to_string(),
        ));
    }

    // Validate payload to ensure all fields are provided
    if payload.name.is_empty() || payload.description.is_empty() || payload.price <= 0.0 {
        return Err(Message::InvalidPayload(
            "Ensure 'name', 'description', 'quantity', and 'price' are provided and valid."
                .to_string(),
        ));
    }

    // Ensure the restaurant exists
    let restaurant = RESTAURANT_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, restaurant)| restaurant.id == payload.restaurant_id)
            .map(|(_, restaurant)| restaurant.clone())
    });
    if restaurant.is_none() {
        return Err(Message::NotFound("Restaurant not found".to_string()));
    }

    // Ensure the user is the owner of the restaurant
    if restaurant.unwrap().owner_id != user.id {
        return Err(Message::UnAuthorized(
            "You do not have permission to add menu items to this restaurant.".to_string(),
        ));
    }

    // Increment the ID counter and create a new menu item
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let menu_item = MenuItem {
        id,
        restaurant_id: payload.restaurant_id,
        name: payload.name,
        description: payload.description,
        price: payload.price,
        quantity_kg: payload.quantity_kg,
        created_at: current_time(),
    };

    // Insert the menu item into the storage and return the menu item
    MENU_STORAGE.with(|storage| storage.borrow_mut().insert(id, menu_item.clone()));
    Ok(menu_item)
}

#[ic_cdk::query]
fn get_menu_items() -> Result<Vec<MenuItem>, Message> {
    MENU_STORAGE.with(|storage| {
        let menu_items: Vec<MenuItem> = storage
            .borrow()
            .iter()
            .map(|(_, item)| item.clone())
            .collect();

        if menu_items.is_empty() {
            Err(Message::NotFound("No menu items found".to_string()))
        } else {
            Ok(menu_items)
        }
    })
}

#[ic_cdk::update]
fn create_order(payload: OrderPayload) -> Result<Order, Message> {
    // Validate payload to ensure all fields are provided
    if payload.items.is_empty() {
        return Err(Message::InvalidPayload(
            "Ensure 'items' are provided.".to_string(),
        ));
    }

    // Validate the customer ID
    let customer_exists = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, user)| user.id == payload.customer_id)
    });
    if !customer_exists {
        return Err(Message::InvalidPayload("Customer not found".to_string()));
    }

    // Ensure the restaurant exists
    let restaurant = RESTAURANT_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, restaurant)| restaurant.id == payload.restaurant_id)
            .map(|(_, restaurant)| restaurant.clone())
    });
    if restaurant.is_none() {
        return Err(Message::NotFound("Restaurant not found".to_string()));
    }

    // Ensure the menu items exist and calculate the total price
    let mut total: f64 = 0.0;
    for item_id in &payload.items {
        let item = MENU_STORAGE.with(|storage| {
            storage
                .borrow()
                .iter()
                .find(|(_, item)| item.id == *item_id)
                .map(|(_, item)| item.clone())
        });
        if item.is_none() {
            return Err(Message::NotFound(format!(
                "Menu item with ID {} not found",
                item_id
            )));
        }
        total += item.unwrap().price;
    }

    // Increment the ID counter and create a new order
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let order = Order {
        id,
        customer_id: payload.customer_id,
        restaurant_id: payload.restaurant_id,
        items: payload.items,
        total_bill: total,
        status: "pending".to_string(),
        created_at: current_time(),
    };

    // Insert the order into the storage and return the order
    ORDER_STORAGE.with(|storage| storage.borrow_mut().insert(id, order.clone()));
    Ok(order)
}

#[ic_cdk::query]
fn get_orders() -> Result<Vec<Order>, Message> {
    ORDER_STORAGE.with(|storage| {
        let orders: Vec<Order> = storage
            .borrow()
            .iter()
            .map(|(_, order)| order.clone())
            .collect();

        if orders.is_empty() {
            Err(Message::NotFound("No orders found".to_string()))
        } else {
            Ok(orders)
        }
    })
}

#[ic_cdk::update]
fn create_delivery(payload: DeliveryPayload) -> Result<Delivery, Message> {
    // Ensure the order exists
    let order = ORDER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, order)| order.id == payload.order_id)
            .map(|(_, order)| order.clone())
    });
    if order.is_none() {
        return Err(Message::NotFound("Order not found".to_string()));
    }

    // Ensure the delivery person exists
    let delivery_person = USER_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, user)| {
                user.id == payload.delivery_person_id && user.role == UserRole::DeliveryPerson
            })
            .map(|(_, user)| user.clone())
    });
    if delivery_person.is_none() {
        return Err(Message::NotFound("Delivery person not found".to_string()));
    }

    // Increment the ID counter and create a new delivery
    let id = ID_COUNTER
        .with(|counter| {
            let current_value = *counter.borrow().get();
            counter.borrow_mut().set(current_value + 1)
        })
        .expect("Cannot increment ID counter");

    let delivery = Delivery {
        id,
        order_id: payload.order_id,
        delivery_person_id: payload.delivery_person_id,
        status: "assigned".to_string(),
        created_at: current_time(),
    };

    // Insert the delivery into the storage and return the delivery
    DELIVERY_STORAGE.with(|storage| storage.borrow_mut().insert(id, delivery.clone()));
    Ok(delivery)
}

#[ic_cdk::query]
fn get_deliveries() -> Result<Vec<Delivery>, Message> {
    DELIVERY_STORAGE.with(|storage| {
        let deliveries: Vec<Delivery> = storage
            .borrow()
            .iter()
            .map(|(_, delivery)| delivery.clone())
            .collect();

        if deliveries.is_empty() {
            Err(Message::NotFound("No deliveries found".to_string()))
        } else {
            Ok(deliveries)
        }
    })
}

// Function for a driver to accept a delivery
#[ic_cdk::update]
fn accept_delivery(
    delivery_id: u64,
    user_payload: AuthenticatedUserPayload,
) -> Result<Delivery, Message> {
    // Authenticate the user
    let user = authenticate_user(user_payload)?;

    // Ensure the user is a delivery person
    if user.role != UserRole::DeliveryPerson {
        return Err(Message::UnAuthorized(
            "You do not have permission to accept a delivery".to_string(),
        ));
    }

    // Ensure the delivery exists
    let delivery = DELIVERY_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, delivery)| delivery.id == delivery_id)
            .map(|(_, delivery)| delivery.clone())
    });
    if let Some(delivery) = delivery {
        // Ensure the delivery person is the one assigned to the delivery
        if delivery.delivery_person_id != user.id {
            return Err(Message::UnAuthorized(
                "You do not have permission to accept this delivery".to_string(),
            ));
        }

        // Update the delivery status to "in transit"
        let updated_delivery = Delivery {
            status: "in transit".to_string(),
            ..delivery
        };
        DELIVERY_STORAGE.with(|storage| {
            storage
                .borrow_mut()
                .insert(delivery_id, updated_delivery.clone())
        });
        Ok(updated_delivery)
    } else {
        Err(Message::NotFound("Delivery not found".to_string()))
    }
}

// Function for a driver to mark a delivery as delivered
#[ic_cdk::update]
fn mark_delivery_as_delivered(
    delivery_id: u64,
    user_payload: AuthenticatedUserPayload,
) -> Result<Delivery, Message> {
    // Authenticate the user
    let user = authenticate_user(user_payload)?;

    // Ensure the user is a delivery person
    if user.role != UserRole::DeliveryPerson {
        return Err(Message::UnAuthorized(
            "You do not have permission to mark a delivery as delivered".to_string(),
        ));
    }

    // Ensure the delivery exists
    let delivery = DELIVERY_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, delivery)| delivery.id == delivery_id)
            .map(|(_, delivery)| delivery.clone())
    });
    if let Some(delivery) = delivery {
        // Ensure the delivery person is the one assigned to the delivery
        if delivery.delivery_person_id != user.id {
            return Err(Message::UnAuthorized(
                "You do not have permission to mark this delivery as delivered".to_string(),
            ));
        }

        // Update the delivery status to "delivered"
        let updated_delivery = Delivery {
            status: "delivered".to_string(),
            ..delivery
        };
        DELIVERY_STORAGE.with(|storage| {
            storage
                .borrow_mut()
                .insert(delivery_id, updated_delivery.clone())
        });
        Ok(updated_delivery)
    } else {
        Err(Message::NotFound("Delivery not found".to_string()))
    }
}

// Update Functions

#[ic_cdk::update]
fn update_user(id: u64, payload: UserPayload) -> Result<User, Message> {
    USER_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        match storage.iter().find(|(_, user)| user.id == id).map(|(_, user)| user.clone()) {
            Some(mut user) => {
                user.username = payload.username;
                user.email = payload.email;
                user.phone_number = payload.phone_number;
                user.role = payload.role;
                storage.insert(id, user.clone());
                Ok(user)
            }
            None => Err(Message::NotFound("User not found".to_string())),
        }
    })
}

#[ic_cdk::update]
fn update_restaurant(id: u64, payload: RestaurantPayload) -> Result<Restaurant, Message> {
    RESTAURANT_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        match storage.iter().find(|(_, restaurant)| restaurant.id == id).map(|(_, restaurant)| restaurant.clone()) {
            Some(mut restaurant) => {
                restaurant.name = payload.name;
                restaurant.description = payload.description;
                restaurant.address = payload.address;
                storage.insert(id, restaurant.clone());
                Ok(restaurant)
            }
            None => Err(Message::NotFound("Restaurant not found".to_string())),
        }
    })
}

#[ic_cdk::update]
fn update_menu_item(id: u64, payload: MenuItemPayload) -> Result<MenuItem, Message> {
    MENU_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        match storage.iter().find(|(_, item)| item.id == id).map(|(_, item)| item.clone()) {
            Some(mut item) => {
                item.name = payload.name;
                item.description = payload.description;
                item.price = payload.price;
                item.quantity_kg = payload.quantity_kg;
                storage.insert(id, item.clone());
                Ok(item)
            }
            None => Err(Message::NotFound("Menu item not found".to_string())),
        }
    })
}

#[ic_cdk::update]
fn update_order(id: u64, payload: OrderPayload) -> Result<Order, Message> {
    ORDER_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        match storage.iter().find(|(_, order)| order.id == id).map(|(_, order)| order.clone()) {
            Some(mut order) => {
                order.customer_id = payload.customer_id;
                order.restaurant_id = payload.restaurant_id;
                order.items = payload.items.clone(); // Clone the items here
                order.status = "updated".to_string();
                order.total_bill = 0.0; // Recalculate total
                for item_id in &payload.items {
                    let item = MENU_STORAGE.with(|storage| {
                        storage
                            .borrow()
                            .iter()
                            .find(|(_, item)| item.id == *item_id)
                            .map(|(_, item)| item.clone())
                    });
                    if let Some(item) = item {
                        order.total_bill += item.price;
                    } else {
                        return Err(Message::NotFound(format!(
                            "Menu item with ID {} not found",
                            item_id
                        )));
                    }
                }
                storage.insert(id, order.clone());
                Ok(order)
            }
            None => Err(Message::NotFound("Order not found".to_string())),
        }
    })
}


#[ic_cdk::update]
fn update_delivery(id: u64, payload: DeliveryPayload) -> Result<Delivery, Message> {
    DELIVERY_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        match storage.iter().find(|(_, delivery)| delivery.id == id).map(|(_, delivery)| delivery.clone()) {
            Some(mut delivery) => {
                delivery.order_id = payload.order_id;
                delivery.delivery_person_id = payload.delivery_person_id;
                delivery.status = "updated".to_string();
                storage.insert(id, delivery.clone());
                Ok(delivery)
            }
            None => Err(Message::NotFound("Delivery not found".to_string())),
        }
    })
}

// Delete Functions

#[ic_cdk::update]
fn delete_user(id: u64) -> Result<Message, Message> {
    USER_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.remove(&id).is_some() {
            Ok(Message::Success("User deleted successfully".to_string()))
        } else {
            Err(Message::NotFound("User not found".to_string()))
        }
    })
}

#[ic_cdk::update]
fn delete_restaurant(id: u64) -> Result<Message, Message> {
    RESTAURANT_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.remove(&id).is_some() {
            Ok(Message::Success("Restaurant deleted successfully".to_string()))
        } else {
            Err(Message::NotFound("Restaurant not found".to_string()))
        }
    })
}

#[ic_cdk::update]
fn delete_menu_item(id: u64) -> Result<Message, Message> {
    MENU_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.remove(&id).is_some() {
            Ok(Message::Success("Menu item deleted successfully".to_string()))
        } else {
            Err(Message::NotFound("Menu item not found".to_string()))
        }
    })
}

#[ic_cdk::update]
fn delete_order(id: u64) -> Result<Message, Message> {
    ORDER_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.remove(&id).is_some() {
            Ok(Message::Success("Order deleted successfully".to_string()))
        } else {
            Err(Message::NotFound("Order not found".to_string()))
        }
    })
}

#[ic_cdk::update]
fn delete_delivery(id: u64) -> Result<Message, Message> {
    DELIVERY_STORAGE.with(|storage| {
        let mut storage = storage.borrow_mut();
        if storage.remove(&id).is_some() {
            Ok(Message::Success("Delivery deleted successfully".to_string()))
        } else {
            Err(Message::NotFound("Delivery not found".to_string()))
        }
    })
}

fn current_time() -> u64 {
    time()
}

#[derive(candid::CandidType, Deserialize, Serialize)]
enum Error {
    NotFound { msg: String },
    UnAuthorized { msg: String },
}

ic_cdk::export_candid!();
