package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/mattn/go-sqlite3"
	"github.com/panprogramadorgh/goquickjwt/pkg/jwt"
	"golang.org/x/crypto/bcrypt"
)

// Estructura de mensajes websocket
type Message struct {
	Type int `json:"type"`
	// Existen diferentes tipos de cuerpos (InfoBody, UsersResBody, LoginResBody, etc)
	Body any `json:"body"`
}

// Cuerpo para mensajes de respuesta de tipo users
type UsersResBody struct {
	Users []User `json:"users"`
}

// Utilizado para identificar credenciales en cuerpos de mensajes de solicitud de tipo register
type LoginReqBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Cuerpo de mensaje de respuesta login
type LoginResBody struct {
	Token string `json:"token"`
}

// Utilizado para definir Users asi como identificar datos del usuario a registrar en el cuerpo de los mensajes register de solicitud
type UserPayload struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Admin     int    `json:"admin"`
}

// Cuerpo de mensaje de respuesta register
type RegisterResBody struct {
	User User `json:"user"`
}

// Cuerpo de mensajes error
type ErrorBody struct {
	Error string `json:"error"`
}

// Cuerpo de mensaje de respuesta de tipo Shout. Shout es el unico tipo de mensaje que queda registrado en la base de datos.
type ShoutResBody struct {
	Owner   int    `json:"owner"`
	Message string `json:"message"`
}

// Cuerpo de mensaje de solicitud de tipo Shout. Shout es el unico tipo de mensaje que queda registrado en la base de datos.
type ShoutReqBody struct {
	Token   string `json:"token"`
	Message string `json:"message"`
}

// Cuerpo de mensaje guet.
type GuestBody struct {
	Message string `json:"message"`
}

// Estructura de usuarios
type User struct {
	UserID int `json:"user_id"`
	UserPayload
}

// Estructura de los claims para los JWT
type JwtPayload struct {
	UserID int `json:"user_id"`
}

/*
Secreto para los jsonwebtokens (modo desarrollo)
*/
const Secret = "aGVsbG8gd29ybGQ="

var MessageTypes = map[string]int{
	"guest":    0,
	"shout":    1,
	"users":    2,
	"login":    3,
	"register": 4,
	"error":    5,
}

// Slice de conexiones websocket
var Connections = []*websocket.Conn{}

// Funciones relacionadas con los usuarios ------

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
func AuthenticateUser(db *sql.DB, c LoginReqBody) (int, string, error) {
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
	// Asegurarse de que el username es unico en la base de datos
	query :=
		`
	SELECT * FROM users WHERE username = "?"
	`
	row := db.QueryRow(query, p.Username)
	if row != nil {
		// Si la fila existe hay que tirar un error
		return fmt.Errorf("%s for username is taken", p.Username)
	}

	// Insertar nuevo usuario
	query =
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

func GetUserByUsername(db *sql.DB, u string) (*User, error) {
	query :=
		`
	SELECT * FROM users WHERE username = ?
	`
	row := db.QueryRow(query, u)
	if row == nil {
		return nil, fmt.Errorf("user with username = %s doesn't exist", u)
	}
	var (
		userID int
		username,
		password,
		firstname,
		lastname string
		admin int
	)
	if err := row.Scan(&userID, &username, &password, &firstname, &lastname, &admin); err != nil {
		return nil, err
	}
	user := &User{
		UserID: userID,
		UserPayload: UserPayload{
			Username:  username,
			Password:  password,
			Firstname: firstname,
			Lastname:  lastname,
			Admin:     admin,
		},
	}
	return user, nil
}

func GetUserById(db *sql.DB, id int) (*User, error) {
	query :=
		`
	SELECT * FROM users WHERE user_id = ?
	`
	row := db.QueryRow(query, id)
	if row == nil {
		return nil, fmt.Errorf("user with user_id = %d doesn't exist", id)
	}
	var (
		userID int
		username,
		password,
		firstname,
		lastname string
		admin int
	)
	if err := row.Scan(&userID, &username, &password, &firstname, &lastname, &admin); err != nil {
		return nil, err
	}
	user := &User{
		UserID: userID,
		UserPayload: UserPayload{
			Username:  username,
			Password:  password,
			Firstname: firstname,
			Lastname:  lastname,
			Admin:     admin,
		},
	}
	return user, nil
}

func GetAllUsers(db *sql.DB) ([]User, error) {
	query :=
		`
	SELECT * FROM users
	`
	rows, err := db.Query(query, nil)
	if err != nil {
		return nil, err
	}
	users := []User{}
	for rows.Next() {
		var (
			userID int
			username,
			password,
			firstname,
			lastname string
			admin int
		)
		if err := rows.Scan(&userID, &username, &password, &firstname, &lastname, &admin); err != nil {
			return nil, err
		}
		users = append(users, User{
			UserID: userID,
			UserPayload: UserPayload{
				Username:  username,
				Password:  password,
				Firstname: firstname,
				Lastname:  lastname,
				Admin:     admin,
			},
		})
	}
	return users, nil
}

// Funciones relacionadas con los mensajes ------

func NewErrorMessage(errBody string) Message {
	return Message{
		Type: MessageTypes["error"],
		Body: ErrorBody{
			Error: errBody,
		},
	}
}

// Funcion encargada de guardar cuerpo de mensajes Shout en la base de datos
func SaveMessage(db *sql.DB, sRes ShoutResBody) error {
	query :=
		`
	INSERT INTO messages (owner, message) VALUES (?, ?)
	`
	_, err := db.Exec(query, sRes.Owner, sRes.Message)
	return err
}

// Funciones de la base de datos ------

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

// Utilidades websocket ------

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// Elimina la conexion del slice de conexiones y la cierra
func ClearConnection(connections *[]*websocket.Conn, conn *websocket.Conn) error {
	for i, eachConn := range *connections {
		if eachConn == conn {
			*connections = append((*connections)[:i], (*connections)[:i+1]...)
			if err := conn.Close(); err != nil {
				return err
			}
			return nil
		}
	}
	return fmt.Errorf("connection %v was not found", conn)
}

// Interfaz de manejadores http compatible con websockets ------

type Handler interface {
	Handle(conn *websocket.Conn) http.HandlerFunc
}

// Definicion del manejador websocket  ------

type WSHandler struct {
	DB          *sql.DB
	Connections *[]*websocket.Conn
}

func (wsh WSHandler) Handle(conn *websocket.Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := ClearConnection(&Connections, conn); err != nil {
				// En caso de que no se pueda cerrar la conexion se muestra el error
				fmt.Println(err)
			}
		}()
		for {
			var m Message
			err := conn.ReadJSON(&m)
			if err != nil {
				fmt.Println(err)
				break
			}
			if m.Type == MessageTypes["guest"] {
				if body, ok := m.Body.(string); ok {
					var guest GuestBody
					if err := json.Unmarshal([]byte(body), &guest); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					if strings.Trim(guest.Message, " ") == "" {
						if err := conn.WriteJSON(NewErrorMessage("invalid message body")); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					for _, eachConn := range *wsh.Connections {
						if err := eachConn.WriteJSON(Message{
							Type: MessageTypes["guest"],
							Body: guest,
						}); err != nil {
							fmt.Println(err)
						}
					}
					continue
				}
				if err := conn.WriteJSON(NewErrorMessage("invalid message body")); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == MessageTypes["shout"] {
				if body, ok := m.Body.(string); ok {
					var sReq ShoutReqBody
					if err := json.Unmarshal([]byte(body), &sReq); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					if strings.Trim(sReq.Message, " ") == "" {
						if err := conn.WriteJSON(NewErrorMessage("invalid message body")); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					rawP, err := jwt.VerifyWithHS256(Secret, sReq.Token)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					pBytes, err := json.Marshal(rawP)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					/* FIXME: Error con la deserializacion json:
					Por algun motivo el valor de la propiedad UserID cambia de 1 a 0.
					*/
					fmt.Println("Serializado: ", string(pBytes))
					var p JwtPayload
					if err := json.Unmarshal(pBytes, &p); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					fmt.Printf("Deserializado: %+v\n", p)

					sRes := ShoutResBody{
						Owner:   p.UserID,
						Message: sReq.Message,
					}

					// Guardar cuerpo del mensaje en la base de datos
					if err := SaveMessage(wsh.DB, sRes); err != nil {
						if err := conn.WriteJSON(err.Error()); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					// Enviar mensaje a todas las conexiones websocket
					for _, eachConn := range *wsh.Connections {
						if err := eachConn.WriteJSON(sRes); err != nil {
							fmt.Println(err)
						}
					}

					continue
				}
				if err := conn.WriteJSON(NewErrorMessage("invalid message body")); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == MessageTypes["users"] {
				users, err := GetAllUsers(wsh.DB)
				if err != nil {
					if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
						fmt.Println(err)
						break
					}
					continue
				}
				if err := conn.WriteJSON(Message{
					Type: MessageTypes["users"],
					Body: UsersResBody{
						Users: users,
					},
				}); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == MessageTypes["login"] {
				if body, ok := m.Body.(string); ok {
					var c LoginReqBody
					if err := json.Unmarshal([]byte(body), &c); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					status, token, err := AuthenticateUser(wsh.DB, c)
					if err != nil {
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
						Type: MessageTypes["login"],
						Body: LoginResBody{
							Token: token,
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
			} else if m.Type == MessageTypes["register"] {
				if body, ok := m.Body.(string); ok {
					var userPayload UserPayload
					if err := json.Unmarshal([]byte(body), &userPayload); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					if err := RegisterUser(wsh.DB, userPayload); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					// Obtener el usuario recien insertado por su username
					user, err := GetUserByUsername(wsh.DB, userPayload.Username)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					resM := Message{
						Type: MessageTypes["register"],
						Body: RegisterResBody{
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
	Next        func(conn *websocket.Conn) http.HandlerFunc
	Connections *[]*websocket.Conn
}

func (m UpgraderMid) Handle(conn *websocket.Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		newConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
		// Agrega la nueva conexion websocker al slice de conexiones
		*m.Connections = append(*m.Connections, newConn)
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
						DB:          db,
						Connections: &Connections,
					}.Handle(conn)
				},
			}.Handle(conn)
		},
		Connections: &Connections,
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
