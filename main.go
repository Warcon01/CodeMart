package main

import (
	"database/sql"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// Global variables for templates, database, and session store.
var (
	tpl   *template.Template
	db    *sql.DB
	store = sessions.NewCookieStore([]byte("a-very-secret-key"))
)

// User represents a registered user.
type User struct {
	ID       int
	Email    string
	Password string
	Name     string
	Surname  string
	Address  string
}

// CartItem представляет товар в корзине.
type CartItem struct {
	ProductID int    `json:"product_id"`
	Name      string `json:"name"`
	Price     int    `json:"price"`
	Quantity  int    `json:"quantity"`
}

// OrderItem represents an item purchased in an order.
type OrderItem struct {
	ProductID   int
	ProductName string
	Quantity    int
	Price       int
}

// OrderWithItems represents an order along with its purchased items.
type OrderWithItems struct {
	OrderID    int
	UserID     int
	CreatedAt  time.Time
	Items      []OrderItem
	TotalPrice int
}

func main() {
	// Register the CartItem type so it can be saved in sessions.
	gob.Register([]CartItem{})

	// Load environment variables from .env file.
	err := godotenv.Load()
	if err != nil {
		log.Println("Warning: .env file not found, continuing with system environment variables")
	}

	// Read PostgreSQL connection details from environment variables.
	host := os.Getenv("PG_HOST")
	port := os.Getenv("PG_PORT")
	user := os.Getenv("PG_USER")
	password := os.Getenv("PG_PASSWORD")
	dbname := os.Getenv("PG_DBNAME")

	// Build the connection string.
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	// Connect to PostgreSQL.
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Error connecting to database:", err)
	}
	defer db.Close()

	// Verify the connection.
	if err = db.Ping(); err != nil {
		log.Fatal("Error pinging database:", err)
	}
	log.Println("Successfully connected to the database.")

	// Parse all templates in the "templates" folder.
	tpl = template.Must(template.ParseGlob("templates/*.html"))

	// Create a new router.
	r := mux.NewRouter()

	// Serve static files from the "static" folder.
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Standard routes.
	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	r.HandleFunc("/register", registerHandler).Methods("GET", "POST")
	r.HandleFunc("/profile", profileHandler).Methods("GET", "POST")
	r.HandleFunc("/admin/product/add", adminAddProductHandler).Methods("GET", "POST")
	r.HandleFunc("/admin/product/delete", adminDeleteProductHandler).Methods("POST")
	r.HandleFunc("/admin/products", adminProductsHandler).Methods("GET")
	r.HandleFunc("/admin/dashboard", adminDashboardHandler).Methods("GET")
	r.HandleFunc("/admin/orders", adminOrdersHandler).Methods("GET")
	r.HandleFunc("/basket", basketHandler).Methods("GET")
	r.HandleFunc("/product", productHandler).Methods("GET")
	r.HandleFunc("/category", categoryHandler).Methods("GET")

	// New endpoints for cart and purchase history.
	r.HandleFunc("/api/cart", apiCartHandler).Methods("GET")
	r.HandleFunc("/api/cart/add", apiAddToCartHandler).Methods("POST")
	r.HandleFunc("/api/cart/delete", apiDeleteFromCartHandler).Methods("POST")
	r.HandleFunc("/checkout", checkoutHandler).Methods("POST")
	r.HandleFunc("/purchase_history", purchaseHistoryHandler).Methods("GET")
	r.HandleFunc("/api/products", apiProductsHandler).Methods("GET")

	// Determine the port to listen on.
	portEnv := os.Getenv("PORT")
	if portEnv == "" {
		portEnv = "9090"
	}
	log.Printf("Server started on http://localhost:%s\n", portEnv)
	if err := http.ListenAndServe(":"+portEnv, r); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

type Product struct {
	ID          int
	Name        string
	Category    string
	Price       int
	ImageURL    string
	Description string
}

// sendReceiptEmail sends a purchase receipt to the specified userEmail.
func sendReceiptEmail(userEmail string, order OrderWithItems) error {
	// Retrieve SMTP configuration from environment variables.
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpUser := os.Getenv("SMTP_USER")
	smtpPass := os.Getenv("SMTP_PASS")

	if smtpHost == "" || smtpPort == "" || smtpUser == "" || smtpPass == "" {
		return fmt.Errorf("SMTP configuration is missing")
	}

	from := smtpUser
	to := []string{userEmail}
	subject := "Your Purchase Receipt from CodeMart"

	// Compose the email body.
	body := fmt.Sprintf("Thank you for your purchase!\n\nOrder #%d was placed on %s.\n\n",
		order.OrderID, order.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	total := 0
	for _, item := range order.Items {
		lineTotal := item.Price * item.Quantity
		body += fmt.Sprintf("%s x %d = %d₸\n", item.ProductName, item.Quantity, lineTotal)
		total += lineTotal
	}
	body += fmt.Sprintf("\nTotal: %d₸\n\nThank you for shopping with CodeMart!", total)

	// Construct the email message.
	msg := []byte("From: " + from + "\r\n" +
		"To: " + userEmail + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"\r\n" +
		body + "\r\n")

	// Set up authentication information.
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)

	// Send the email.
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, to, msg)
	return err
}

// homeHandler renders the homepage with a simple product listing.
func homeHandler(w http.ResponseWriter, r *http.Request) {
	// Fetch products from the database
	rows, err := db.Query("SELECT id, name, price, image_url, description FROM products ORDER BY created_at DESC")
	if err != nil {
		log.Println("Error fetching products from database:", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Price, &p.ImageURL, &p.Description); err != nil {
			log.Println("Error scanning product:", err)
			continue
		}
		products = append(products, p)
	}

	// Check if the user is logged in
	session, _ := store.Get(r, "session")
	isLoggedIn := false
	if _, ok := session.Values["user_id"].(int); ok {
		isLoggedIn = true
	}

	// Pass data to the template
	data := map[string]interface{}{
		"Products":   products,
		"IsLoggedIn": isLoggedIn, // Login status flag
	}

	// Render the template
	if err := tpl.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Println("Error rendering template:", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// loginHandler handles both GET and POST requests for user login.
func loginHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	if r.Method == http.MethodGet {
		if err := tpl.ExecuteTemplate(w, "login.html", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	if email == "" || password == "" {
		renderTemplateWithError(w, "login.html", "Email and password are required.")
		return
	}

	var user User
	err := db.QueryRow("SELECT id, email, password FROM users WHERE email = $1", email).
		Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		renderTemplateWithError(w, "login.html", "Invalid email or password.")
		return
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		renderTemplateWithError(w, "login.html", "Invalid email or password.")
		return
	}

	// Set the admin flag.
	if user.Email == "admin@example.com" {
		session.Values["is_admin"] = true
	} else {
		session.Values["is_admin"] = false
	}

	session.Values["user_id"] = user.ID
	session.Save(r, w)

	// Redirect admins to a dedicated admin dashboard, others to homepage.
	if session.Values["is_admin"].(bool) {
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	delete(session.Values, "user_id")
	delete(session.Values, "is_admin")
	session.Save(r, w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// registerHandler processes user registration requests.
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if err := tpl.ExecuteTemplate(w, "register.html", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Process POST registration.
	email := r.FormValue("email")
	password := r.FormValue("password")
	passwordConfirm := r.FormValue("password_confirm")

	if email == "" || password == "" || passwordConfirm == "" {
		renderTemplateWithError(w, "register.html", "All fields are required.")
		return
	}

	emailRegex := regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
	if !emailRegex.MatchString(email) {
		renderTemplateWithError(w, "register.html", "Invalid email address.")
		return
	}

	if password != passwordConfirm {
		renderTemplateWithError(w, "register.html", "Passwords do not match.")
		return
	}

	if len(password) < 6 {
		renderTemplateWithError(w, "register.html", "Password must be at least 6 characters long.")
		return
	}

	var exists bool
	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)", email).Scan(&exists)
	if err != nil {
		renderTemplateWithError(w, "register.html", "Error checking existing email.")
		return
	}
	if exists {
		renderTemplateWithError(w, "register.html", "Email already registered.")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		renderTemplateWithError(w, "register.html", "Error processing password.")
		return
	}

	_, err = db.Exec("INSERT INTO users (email, password, created_at) VALUES ($1, $2, $3)",
		email, string(hashedPassword), time.Now())
	if err != nil {
		renderTemplateWithError(w, "register.html", "Error registering user.")
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// profileHandler handles GET and POST requests for the profile page.
func profileHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	// Retrieve user_id from session and convert to int.
	var userID int
	if id, ok := session.Values["user_id"].(int); ok {
		userID = id
	} else if idStr, ok := session.Values["user_id"].(string); ok {
		var err error
		userID, err = strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "Invalid session data", http.StatusUnauthorized)
			return
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var user User

	if r.Method == http.MethodPost {
		// Read form values.
		name := r.FormValue("name")
		surname := r.FormValue("surname")
		address := r.FormValue("address")
		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")

		// Retrieve the current user record (including password) from the database.
		err := db.QueryRow(
			`SELECT id, email, password, 
                    COALESCE(name, '') AS name, 
                    COALESCE(surname, '') AS surname, 
                    COALESCE(address, '') AS address 
             FROM users WHERE id = $1`, userID).
			Scan(&user.ID, &user.Email, &user.Password, &user.Name, &user.Surname, &user.Address)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// If new password is provided, handle password change.
		if newPassword != "" || confirmPassword != "" {
			if newPassword != confirmPassword {
				tpl.ExecuteTemplate(w, "profile.html", map[string]interface{}{
					"User":  user,
					"Error": "New password and confirmation do not match.",
				})
				return
			}
			// Check if current password is correct.
			err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword))
			if err != nil {
				tpl.ExecuteTemplate(w, "profile.html", map[string]interface{}{
					"User":  user,
					"Error": "Current password is incorrect.",
				})
				return
			}
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			if err != nil {
				tpl.ExecuteTemplate(w, "profile.html", map[string]interface{}{
					"User":  user,
					"Error": "Error processing new password.",
				})
				return
			}
			// Update all fields including password.
			_, err = db.Exec("UPDATE users SET name = $1, surname = $2, address = $3, password = $4 WHERE id = $5",
				name, surname, address, string(hashedPassword), userID)
			if err != nil {
				tpl.ExecuteTemplate(w, "profile.html", map[string]interface{}{
					"User":  user,
					"Error": "Failed to update profile.",
				})
				return
			}
		} else {
			// Update only name, surname, and address.
			_, err := db.Exec("UPDATE users SET name = $1, surname = $2, address = $3 WHERE id = $4",
				name, surname, address, userID)
			if err != nil {
				tpl.ExecuteTemplate(w, "profile.html", map[string]interface{}{
					"User":  user,
					"Error": "Failed to update profile.",
				})
				return
			}
		}

		// Retrieve updated user data.
		err = db.QueryRow(
			`SELECT id, email, 
                    COALESCE(name, '') AS name, 
                    COALESCE(surname, '') AS surname, 
                    COALESCE(address, '') AS address 
             FROM users WHERE id = $1`, userID).
			Scan(&user.ID, &user.Email, &user.Name, &user.Surname, &user.Address)
		if err != nil {
			http.Error(w, "Failed to retrieve updated profile", http.StatusInternalServerError)
			return
		}

		tpl.ExecuteTemplate(w, "profile.html", map[string]interface{}{
			"User":    user,
			"Success": "Profile updated successfully.",
		})
		return
	}

	// For GET requests, simply retrieve and display the user's profile.
	err := db.QueryRow(
		`SELECT id, email, 
                COALESCE(name, '') AS name, 
                COALESCE(surname, '') AS surname, 
                COALESCE(address, '') AS address 
         FROM users WHERE id = $1`, userID).
		Scan(&user.ID, &user.Email, &user.Name, &user.Surname, &user.Address)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	tpl.ExecuteTemplate(w, "profile.html", map[string]interface{}{
		"User": user,
	})
}

// adminAddProductHandler handles GET and POST requests for adding new products.
func adminAddProductHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	// Проверяем, что юзер - админ.
	isAdmin, ok := session.Values["is_admin"].(bool)
	if !ok || !isAdmin {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		tpl.ExecuteTemplate(w, "admin_add_product.html", nil)
		return
	}

	// Получаем данные из формы.
	name := r.FormValue("name")
	category := r.FormValue("category")
	description := r.FormValue("description")
	priceStr := r.FormValue("price")
	imageURL := r.FormValue("image_url")

	if name == "" || category == "" || priceStr == "" || imageURL == "" {
		tpl.ExecuteTemplate(w, "admin_add_product.html", map[string]string{"Error": "All fields are required."})
		return
	}

	price, err := strconv.Atoi(priceStr)
	if err != nil {
		tpl.ExecuteTemplate(w, "admin_add_product.html", map[string]string{"Error": "Price must be a number."})
		return
	}

	// Сохраняем товар в БД.
	_, err = db.Exec("INSERT INTO products (name, category, description, price, image_url, created_at) VALUES ($1, $2, $3, $4, $5, NOW())",
		name, category, description, price, imageURL)

	if err != nil {
		tpl.ExecuteTemplate(w, "admin_add_product.html", map[string]string{"Error": "Error adding product."})
		return
	}

	tpl.ExecuteTemplate(w, "admin_add_product.html", map[string]string{"Success": "Product added successfully!"})
}

// adminDeleteProductHandler removes a product from the database.
func adminDeleteProductHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	// Check if the user is admin.
	isAdmin, ok := session.Values["is_admin"].(bool)
	if !ok || !isAdmin {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	productIDStr := r.FormValue("product_id")
	productID, err := strconv.Atoi(productIDStr)
	if err != nil {
		http.Error(w, "Invalid product id", http.StatusBadRequest)
		return
	}

	// Delete product from the database.
	_, err = db.Exec("DELETE FROM products WHERE id = $1", productID)
	if err != nil {
		http.Error(w, "Failed to delete product: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// adminProductsHandler displays all products with options to delete.
func adminProductsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	isAdmin, ok := session.Values["is_admin"].(bool)
	if !ok || !isAdmin {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query("SELECT id, name, category, price, image_url FROM products ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Category, &p.Price, &p.ImageURL); err != nil {
			log.Println("Error scanning product:", err)
			continue
		}
		products = append(products, p)
	}

	data := map[string]interface{}{
		"Products": products,
	}

	if err := tpl.ExecuteTemplate(w, "admin_products.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// adminDashboardHandler displays the admin dashboard page.
func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	// Check if the user is an admin.
	isAdmin, ok := session.Values["is_admin"].(bool)
	if !ok || !isAdmin {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Render the admin dashboard template.
	if err := tpl.ExecuteTemplate(w, "admin_dashboard.html", nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// basketHandler renders the basket page with current cart items.
func basketHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	var cart []CartItem
	if session.Values["cart"] != nil {
		if c, ok := session.Values["cart"].([]CartItem); ok {
			cart = c
		}
	}

	// Check if the user is logged in
	isLoggedIn := false
	if _, ok := session.Values["user_id"].(int); ok {
		isLoggedIn = true
	}

	// Pass data to the template
	data := map[string]interface{}{
		"Cart":       cart,
		"IsLoggedIn": isLoggedIn, // Login status flag
	}

	if err := tpl.ExecuteTemplate(w, "basket.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// apiCartHandler returns the current cart items as JSON.
func apiCartHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	var cart []CartItem

	// Извлекаем корзину из сессии
	if session.Values["cart"] != nil {
		cart, _ = session.Values["cart"].([]CartItem)
	}

	// Отправляем корзину в JSON-формате
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"items": cart})
}

// apiAddToCartHandler adds a product to the cart.
// It expects form values: product_id, name, price, and optionally quantity.
func apiAddToCartHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	// Получаем данные из запроса
	productID, err := strconv.Atoi(r.FormValue("product_id"))
	if err != nil {
		http.Error(w, "Invalid product_id", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	price, err := strconv.Atoi(r.FormValue("price"))
	if err != nil {
		http.Error(w, "Invalid price", http.StatusBadRequest)
		return
	}
	quantity := 1 // По умолчанию 1
	if q, err := strconv.Atoi(r.FormValue("quantity")); err == nil && q > 0 {
		if q > 1 {
			quantity = quantity + q - 1
		} else {
			quantity = q
		}
	}

	// Получаем текущую корзину
	var cart []CartItem
	if session.Values["cart"] != nil {
		cart, _ = session.Values["cart"].([]CartItem)
	}

	// Проверяем, есть ли товар уже в корзине
	found := false
	for i, item := range cart {
		if item.ProductID == productID {
			cart[i].Quantity += quantity
			found = true
			break
		}
	}

	// Если товара нет в корзине, добавляем его
	if !found {
		cart = append(cart, CartItem{
			ProductID: productID,
			Name:      name,
			Price:     price,
			Quantity:  quantity,
		})
	}

	// Сохраняем корзину в сессию
	session.Values["cart"] = cart
	session.Save(r, w)

	// Отправляем ответ
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// apiDeleteFromCartHandler removes an item from the session cart.
// apiDeleteFromCartHandler removes an item from the session cart.
func apiDeleteFromCartHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	// Получаем ID товара
	productID, err := strconv.Atoi(r.FormValue("product_id"))
	if err != nil {
		http.Error(w, "Invalid product_id", http.StatusBadRequest)
		return
	}

	// Получаем текущую корзину
	var cart []CartItem
	if session.Values["cart"] != nil {
		cart, _ = session.Values["cart"].([]CartItem)
	}

	// Удаляем товар из корзины
	newCart := []CartItem{}
	for _, item := range cart {
		if item.ProductID != productID {
			newCart = append(newCart, item)
		}
	}

	// Обновляем сессию
	session.Values["cart"] = newCart
	session.Save(r, w)

	// Отправляем ответ
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// checkoutHandler processes the checkout by saving the order and order items in the database.
func checkoutHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve session.
	session, err := store.Get(r, "session")
	if err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	// Retrieve the user_id from session.
	var userID int
	if id, ok := session.Values["user_id"].(int); ok {
		userID = id
	} else if idStr, ok := session.Values["user_id"].(string); ok {
		var err error
		userID, err = strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, "Invalid session data", http.StatusUnauthorized)
			return
		}
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve the cart from session.
	var cart []CartItem
	if session.Values["cart"] != nil {
		if c, ok := session.Values["cart"].([]CartItem); ok {
			cart = c
		}
	}
	if len(cart) == 0 {
		http.Error(w, "Cart is empty", http.StatusBadRequest)
		return
	}

	// Begin a transaction.
	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Insert a new order and get its ID.
	var orderID int
	now := time.Now()
	err = tx.QueryRow("INSERT INTO orders (user_id, created_at) VALUES ($1, $2) RETURNING id", userID, now).Scan(&orderID)
	if err != nil {
		tx.Rollback()
		http.Error(w, "Failed to create order", http.StatusInternalServerError)
		return
	}

	// Insert each cart item into the order_items table.
	for _, item := range cart {
		_, err = tx.Exec("INSERT INTO order_items (order_id, product_id, product_name, quantity, price) VALUES ($1, $2, $3, $4, $5)",
			orderID, item.ProductID, item.Name, item.Quantity, item.Price)
		if err != nil {
			tx.Rollback()
			http.Error(w, "Failed to add order items", http.StatusInternalServerError)
			return
		}
	}

	// Commit the transaction.
	if err = tx.Commit(); err != nil {
		http.Error(w, "Failed to complete order", http.StatusInternalServerError)
		return
	}

	// Construct an order object to send in the receipt email.
	order := OrderWithItems{
		OrderID:   orderID,
		CreatedAt: now,
		Items:     []OrderItem{},
	}
	for _, item := range cart {
		order.Items = append(order.Items, OrderItem{
			ProductID:   item.ProductID,
			ProductName: item.Name,
			Quantity:    item.Quantity,
			Price:       item.Price,
		})
	}

	// Retrieve the user's email from the database.
	var userEmail string
	err = db.QueryRow("SELECT email FROM users WHERE id = $1", userID).Scan(&userEmail)
	if err != nil {
		fmt.Println("Failed to retrieve user email:", err)
	} else {
		// Send the receipt email.
		err = sendReceiptEmail(userEmail, order)
		if err != nil {
			fmt.Println("Error sending receipt email:", err)
			// You can decide whether to alert the user or simply log this error.
		}
	}

	// Clear the cart in the session.
	session.Values["cart"] = []CartItem{}
	session.Save(r, w)

	// Redirect the user to the purchase history page.
	http.Redirect(w, r, "/purchase_history", http.StatusSeeOther)
}

// purchaseHistoryHandler displays the purchase history (orders) for the logged-in user.
func purchaseHistoryHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["user_id"]
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Retrieve and clear any flash message.
	var flash string
	if f, ok := session.Values["flash"].(string); ok {
		flash = f
		delete(session.Values, "flash")
		session.Save(r, w)
	}

	var orders []OrderWithItems
	rows, err := db.Query("SELECT id, created_at FROM orders WHERE user_id = $1 ORDER BY created_at DESC", userID)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var order OrderWithItems
		if err := rows.Scan(&order.OrderID, &order.CreatedAt); err != nil {
			continue
		}

		itemRows, err := db.Query("SELECT product_id, product_name, quantity, price FROM order_items WHERE order_id = $1", order.OrderID)
		if err == nil {
			defer itemRows.Close()
			for itemRows.Next() {
				var item OrderItem
				if err := itemRows.Scan(&item.ProductID, &item.ProductName, &item.Quantity, &item.Price); err == nil {
					order.Items = append(order.Items, item)
				}
			}
		}
		orders = append(orders, order)
	}

	data := map[string]interface{}{
		"Orders": orders,
		"Flash":  flash,
	}
	if err := tpl.ExecuteTemplate(w, "purchase_history.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// renderTemplateWithError renders a template and passes an error message to it.
func renderTemplateWithError(w http.ResponseWriter, tmpl string, errorMsg string) {
	data := map[string]string{"Error": errorMsg}
	if err := tpl.ExecuteTemplate(w, tmpl, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func adminOrdersHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	isAdmin, ok := session.Values["is_admin"].(bool)
	if !ok || !isAdmin {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query("SELECT id, user_id, created_at FROM orders ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var orders []OrderWithItems
	for rows.Next() {
		var order OrderWithItems
		if err := rows.Scan(&order.OrderID, &order.UserID, &order.CreatedAt); err != nil {
			continue
		}

		// Получаем товары внутри заказа
		itemRows, err := db.Query("SELECT product_id, product_name, quantity, price FROM order_items WHERE order_id = $1", order.OrderID)
		if err == nil {
			defer itemRows.Close()
			totalPrice := 0 // Переносим подсчет суммы сюда
			for itemRows.Next() {
				var item OrderItem
				if err := itemRows.Scan(&item.ProductID, &item.ProductName, &item.Quantity, &item.Price); err == nil {
					order.Items = append(order.Items, item)
					totalPrice += item.Quantity * item.Price // Считаем сумму заказа
				}
			}
			order.TotalPrice = totalPrice // Добавляем итоговую сумму в структуру
		}

		orders = append(orders, order)
	}

	data := map[string]interface{}{
		"Orders": orders,
	}

	if err := tpl.ExecuteTemplate(w, "admin_orders.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func productHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")

	productID := r.URL.Query().Get("id")
	if productID == "" {
		http.Error(w, "Product ID is required", http.StatusBadRequest)
		return
	}

	var product Product
	err := db.QueryRow("SELECT id, name, price, image_url, description FROM products WHERE id = $1", productID).
		Scan(&product.ID, &product.Name, &product.Price, &product.ImageURL, &product.Description)

	if err != nil {
		http.Error(w, "Product not found", http.StatusNotFound)
		return
	}

	isLoggedIn := false
	if _, ok := session.Values["user_id"].(int); ok {
		isLoggedIn = true
	}

	// Pass data to the template
	data := map[string]interface{}{
		"Product":    product,
		"IsLoggedIn": isLoggedIn, // Login status flag
	}

	if err := tpl.ExecuteTemplate(w, "product.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func apiProductsHandler(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")

	query := "SELECT id, name, price, image_url FROM products"
	var rows *sql.Rows
	var err error

	if category != "" && category != "All" {
		query += " WHERE category = $1"
		rows, err = db.Query(query, category)
	} else {
		rows, err = db.Query(query)
	}

	if err != nil {
		http.Error(w, "Error retrieving products", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Price, &p.ImageURL); err != nil {
			continue
		}
		products = append(products, p)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"Products": products})
}

func categoryHandler(w http.ResponseWriter, r *http.Request) {
	category := r.URL.Query().Get("category")
	if category == "" {
		http.Error(w, "Category not specified", http.StatusBadRequest)
		return
	}

	rows, err := db.Query("SELECT id, name, price, image_url FROM products WHERE category = $1", category)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var products []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Price, &p.ImageURL); err != nil {
			log.Println("Error scanning product:", err)
			continue
		}
		products = append(products, p)
	}

	session, _ := store.Get(r, "session")
	isLoggedIn := false
	if _, ok := session.Values["user_id"]; ok {
		isLoggedIn = true
	}

	data := map[string]interface{}{
		"Category":   category,
		"Products":   products,
		"IsLoggedIn": isLoggedIn,
	}

	if err := tpl.ExecuteTemplate(w, "category.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
