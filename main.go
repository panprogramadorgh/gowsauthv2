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
	Type int    `json:"type"`
	Body string `json:"body"`
}

type UserCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type JwtPayload struct {
	UserID int `json:"user_id"`
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

type LoginRes struct {
	Token string `json:"token"`
}

/*
Secreto para los jsonwebtokens (modo desarrollo)
*/
const Secret = "aGVsbG8gd29ybGQ="

var messageTypes = map[string]int{
	"info":  0,
	"login": 1,
	"error": 2,
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

status == 1 - err.Error() == {Username: "xx", Password: "xx"} invalid credentials

status == 2 - err.Error() == internal server error
*/
func AuthenticateUser(db *sql.DB, c UserCredentials) (int, string, error) {
	query :=
		`
	SELECT * FROM users WHERE username = ? AND VERIFY(password, ?)
	`
	rows, err := db.Query(query, c.Username, c.Password)
	if err != nil {
		return 2, "", err
	}

	var user *User = nil
	for rows.Next() {
		// var UserID int
		// var Username string
		// var Password string
		// var Firstname string
		// var Lastname string
		// var Admin bool

		user = &User{}
		err := rows.Scan(&user.UserID, &user.Username, &user.Password, &user.Firstname, &user.Lastname, &user.Admin)
		if err != nil {
			return 2, "", err
		}
	}
	if user == nil {
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

func NewErrorMessage(errBody string) Message {
	return Message{
		Type: messageTypes["error"],
		Body: errBody,
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
			var m *Message = nil
			err := conn.ReadJSON(&m)
			if err != nil {
				fmt.Println(err)
				break
			}
			if m.Type == messageTypes["info"] {
				resM := Message{
					Type: messageTypes["info"],
					Body: "Hello World",
				}
				if err := conn.WriteJSON(resM); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == messageTypes["login"] {
				var c UserCredentials
				if err := json.Unmarshal([]byte(m.Body), &c); err != nil {
					if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
						fmt.Println(err)
						break
					}
				} else {
					status, token, err := AuthenticateUser(wsh.DB, c)
					if err != nil {
						fmt.Println(status, err)
						errMessage := "internal server error"
						if status == 1 {
							errMessage = err.Error()
						}
						if err := conn.WriteJSON(NewErrorMessage(errMessage)); err != nil {
							fmt.Println(err)
							break
						}
					} else {
						// Success response
						lr := LoginRes{
							Token: token,
						}
						jlr, err := json.Marshal(lr)
						if err != nil {
							if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
								fmt.Println(err)
								break
							}
						}
						resM := Message{
							Type: messageTypes["info"],
							Body: string(jlr),
						}
						if err := conn.WriteJSON(resM); err != nil {
							fmt.Println(err)
							return
						}
					}
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
