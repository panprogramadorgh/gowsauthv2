package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/websocket"
	"github.com/mattn/go-sqlite3"
	"github.com/panprogramadorgh/goquickjwt/pkg/jwt"
	"golang.org/x/crypto/bcrypt"
)

type Message struct {
	Type int `json:"type"`
	Body any `json:"body"`
}

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResMessage struct {
	Token string `json:"token"`
}

type RegisterResMessage struct {
	User User
}

type UserPayload struct {
	UserCredentials
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Admin     int    `json:"admin"`
}

type User struct {
	UserID int `json:"user_id"`
	UserPayload
}

type ErrorMessage struct {
	Error string `json:"error"`
}

type InfoMessage struct {
	Message string `json:"message"`
}

type JwtPayload struct {
	UserID int `json:"user_id"`
}

/*
Secreto para los jsonwebtokens (modo desarrollo)
*/
const Secret = "aGVsbG8gd29ybGQ="

var messageTypes = map[string]int{
	"info":     0,
	"login":    1,
	"register": 2,
	"error":    3,
}

func (p *UserPayload) HashPassword() error {
	hash, err := bcrypt.GenerateFromPassword([]byte(p.Password), 16)
	if err != nil {
		return err
	}
	p.Password = string(hash)
	return nil
}

func VerifyPassword(hash string, password string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return false
	}
	return true
}

func (t JwtPayload) NewToken(secret string) (string, error) {
	p := jwt.Payload{
		"UserID": t.UserID,
	}
	token, err := p.SignWithHS256(secret)
	if err != nil {
		return "", err
	}
	return token, nil
}

/*
status, token, err := AuthenticateUser(db, c)

status == 0 - err == nil

status == 1 - err.Error() == {Username: xx, Password: xx} invalid credentials

status == 2 - err.Error() == internal server error
*/
func AuthenticateUser(db *sql.DB, c UserCredentials) (int, string, error) {
	query :=
		`
	SELECT * FROM users WHERE username = ? AND VERIFY(password, ?)
	`
	row := db.QueryRow(query, c.Username, c.Password)

	var user User = User{}
	err := row.Scan(&user.UserID, &user.Username, &user.Password, &user.Firstname, &user.Lastname, &user.Admin)
	if err != nil {
		return 1, "", fmt.Errorf("%+v invalid credentials", c)
	}

	p := JwtPayload{
		UserID: user.UserID,
	}
	token, err := p.NewToken(Secret)
	if err != nil {
		return 2, "", err
	}
	return 0, token, nil
}

func RegisterUser(db *sql.DB, p UserPayload) error {
	query :=
		`
	INSERT INTO users (username, password, firstname, lastname, admin) VALUES (?, ?, ?, ?, ?)
	`
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(p.Password), 16)
	if err != nil {
		return err
	}
	if _, err := db.Exec(query, p.Username, hashedPassword, p.Firstname, p.Lastname, p.Admin); err != nil {
		return err
	}
	return nil
}

func GetUser(db *sql.DB, u string) *User {
	query :=
		`
	SELECT * FROM users WHERE username = ?
	`
	row := db.QueryRow(query, u)
	if row == nil {
		return nil
	}
	var (
		userID int
		username,
		password,
		firstname,
		lastname string
		admin int
	)
	row.Scan(&userID, &username, &password, &firstname, &lastname, &admin)
	user := &User{
		UserID: userID,
		UserPayload: UserPayload{
			UserCredentials: UserCredentials{
				Username: username,
				Password: password,
			},
			Firstname: firstname,
			Lastname:  lastname,
			Admin:     admin,
		},
	}
	return user
}

func NewErrorMessage(errBody string) Message {
	return Message{
		Type: messageTypes["error"],
		Body: ErrorMessage{
			Error: errBody,
		},
	}
}

func Connect(url string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", url)
	if err != nil {
		return nil, err
	}
	return db, nil
}

func RegisterSQLFunc(db *sql.DB, n string, f any) error {
	conn, err := db.Conn(context.Background())
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Raw(func(driverConn any) error {
		sqliteConn := driverConn.(*sqlite3.SQLiteConn)
		return sqliteConn.RegisterFunc(n, f, true)
	}); err != nil {
		return err
	}
	return nil
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Handler interface {
	Handle(conn *websocket.Conn) http.HandlerFunc
}

type WSHandler struct {
	DB *sql.DB
}

func (wsh WSHandler) Handle(conn *websocket.Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer conn.Close()
		for {
			var m Message
			err := conn.ReadJSON(&m)
			if err != nil {
				fmt.Println(err)
				break
			}
			if m.Type == messageTypes["info"] {
				if body, ok := m.Body.(string); ok {
					var info InfoMessage
					if err := json.Unmarshal([]byte(body), &info); err != nil {
						fmt.Println(err)
						break
					}
					if err := conn.WriteJSON(Message{
						Type: messageTypes["info"],
						Body: info,
					}); err != nil {
						fmt.Println(err)
						break
					}
					continue
				}
				if err := conn.WriteJSON(NewErrorMessage("invalid message body")); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == messageTypes["login"] {
				if body, ok := m.Body.(string); ok {
					var c UserCredentials
					if err := json.Unmarshal([]byte(body), &c); err != nil {
						fmt.Println(err)
						break
					}

					status, token, err := AuthenticateUser(wsh.DB, c)
					if err != nil {
						fmt.Println(err)
						errMessage := "internal server error"
						if status == 1 {
							errMessage = err.Error()
						}
						if err := conn.WriteJSON(NewErrorMessage(errMessage)); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					// Success response
					resM := Message{
						Type: messageTypes["login"],
						Body: LoginResMessage{
							Token: token,
						},
					}
					if err := conn.WriteJSON(resM); err != nil {
						fmt.Println(err)
						break
					}

					continue
				}
				if err := conn.WriteJSON(NewErrorMessage("invalid message bodys")); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == messageTypes["register"] {
				if body, ok := m.Body.(string); ok {
					var userPayload UserPayload
					if err := json.Unmarshal([]byte(body), &userPayload); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						break
					}

					if err := RegisterUser(wsh.DB, userPayload); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						break
					}

					user := GetUser(wsh.DB, userPayload.Username)

					resM := Message{
						Type: messageTypes["register"],
						Body: RegisterResMessage{
							User: *user,
						},
					}
					if err := conn.WriteJSON(resM); err != nil {
						fmt.Println(err)
						break
					}
					continue
				}
				if err := conn.WriteJSON(NewErrorMessage("invalid message body")); err != nil {
					fmt.Println(err)
					break
				}
			} else {
				if err := conn.WriteJSON(NewErrorMessage("invalid message type")); err != nil {
					fmt.Println(err)
					break
				}
			}
		}
	}
}

type UpgraderMid struct {
	Next func(conn *websocket.Conn) http.HandlerFunc
}

func (m UpgraderMid) Handle(conn *websocket.Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		newConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
		m.Next(newConn).ServeHTTP(w, r)
	}
}

type DatabaseMid struct {
	DB   *sql.DB
	Next func(conn *websocket.Conn) http.HandlerFunc
}

func (m DatabaseMid) Handle(conn *websocket.Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := m.DB.Ping()
		if err != nil {
			fmt.Println(err)
			if err := conn.WriteJSON(NewErrorMessage("cannot connect to database")); err != nil {
				fmt.Println(err)
				return
			}
			return
		}
		m.Next(conn).ServeHTTP(w, r)
	}
}

func main() {
	db, err := Connect("./database.db")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	if err := RegisterSQLFunc(db, "VERIFY", VerifyPassword); err != nil {
		fmt.Println(err)
		return
	}

	wshandler := UpgraderMid{
		Next: func(conn *websocket.Conn) http.HandlerFunc {
			return DatabaseMid{
				DB: db,
				Next: func(conn *websocket.Conn) http.HandlerFunc {
					return WSHandler{
						DB: db,
					}.Handle(conn)
				},
			}.Handle(conn)
		},
	}

	http.HandleFunc("/ws", wshandler.Handle(nil))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./index.html")
	})
	fmt.Println("Server running on 3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		fmt.Println(err)
		return
	}
}
