package db

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3" // _ later use
)

var DB *sql.DB

func InitDB() {
	var err error
	// Assign the result of sql.Open to the global DB variable
	DB, err = sql.Open("sqlite3", "api.db")
	if err != nil {
		panic("Could not connect to database.")
	}

	// Manage the database connection
	DB.SetMaxOpenConns(10)
	DB.SetMaxIdleConns(5)

	// Call createTables to initialize the tables
	createTables()
}

// ` ` is create a string multiple lines
func createTables() {

	createUserTable := `
	CREATE TABLE IF NOT EXISTS users(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	email TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL
    )
	`
	_, err := DB.Exec(createUserTable)

	if err != nil {
		panic("Could not create the users table.")
	}

	createEventTable := `
	CREATE TABLE IF NOT EXISTS events(
	   id INTEGER PRIMARY KEY AUTOINCREMENT,
	   name TEXT NOT NULL,
	   description TEXT NOT NULL,
	   location TEXT NOT NULL,
	   dateTime DATETIME NOT NULL,
	   user_id INTEGER,
       FOREIGN KEY(user_id) REFERENCE users(id)
	)
	`

	_, err = DB.Exec(createEventTable)

	if err != nil {
		panic("Could not create events table.")
	}

	createRegistrationTable := `
	CREATE TABLE IF NOT EXISTS registrations(
	  id INTEGER PRIMARY KEY AUTOINCREMENT,
	  event_id INTEGER,
	  user_id INTEGER,
	  FOREIGN KEY(event_id) REFERENCE events(id)
	  FOREIGN KEY(user_id) REFERENCE users(id)
    )
	`
	_,err = DB.Exec(createRegistrationTable)
	if err != nil{
		panic("Could not create registrations table.")
	}
}
