package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"

	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"github.com/panprogramadorgh/goquickjwt/pkg/jwt"
	"golang.org/x/crypto/bcrypt"
)

// Definicion de estructuras para los principales items del websocket ------

// Estructura de mensajes websocket
type WSMessage struct {
	/*
		// Diferentes tipos de mensajes
		var MessageTypes = map[string]int{
			"guest":    0,
			"shout":    1,
			"users":    2,
			"messages": 3,
			"whoami":   4,
			"login":    5,
			"register": 6,
			"weight":   7,
			"error":    8,
		}

		loginMsgType := MessageTypes["login"]

		wsm := WSMessage{
			Type: loginMsgType,
			Body: LoginMsgResBody{
				Token: "xxx.xxx.xxx"
			}
		}
	*/
	Type int `json:"type"`
	// En funcion del tipo de WSMessage hay diferentes cuerpos. Por ejemplo si queremos identificarnos como un usuario, tendremos que enviar desde el cliente un mensaje de tipo login con el correspondiente cuerpo teniendo en cuenta que es un mensaje login de peticion; en este caso deberiamos enviar un cuerpo de tipo LoginMsgReqBody
	Body any `json:"body"`
}

// Estructura de mensaje (a guardar en la base de datos tras mandar mensaje websocket shout)
type Message struct {
	MessageID int    `json:"message_id"`
	Owner     int    `json:"owner"`
	Message   string `json:"message"`
}

// Estructura de usuarios
type User struct {
	UserID int `json:"user_id"`
	UserPayload
}

// Agrupa los campos necesarios para definir un usuario
type UserPayload struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Firstname string `json:"firstname"`
	Lastname  string `json:"lastname"`
	Admin     bool   `json:"admin"`
}

// Estructura de los claims para los JWT
type JwtPayload struct {
	UserID int
}

// Cuerpo de mensajes messages (respuesta)
type MessagesMsgBody struct {
	Messages []Message `json:"messages"`
}

// Cuerpo de mensaje weigth (respuesta)
type WeigthMsgBody struct {
	Weigth int `json:"weigth"`
}

// Cuerpo de mensajes error (respuesta)
type ErrorMsgBody struct {
	Error string `json:"error"`
}

// Cuerpos asociados mensajes websocket con entrada de datos del cliente (ejemplo: cuerpos para mensajes de tipo login, los cuales reciben credenciales de un cliente) ------

// Cuerpo de mensajes users (respuesta)
type UsersMsgReqBody struct {
	Token string `json:"token"`
}

// Cuerpo de mensajes users (respuesta)
type UsersMsgResBody struct {
	Users []User `json:"users"`
}

// Cuerpo de mensaje login (solicitud)
type LoginMsgReqBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Cuerpo de mensaje login (respuesta)
type LoginMsgResBody struct {
	Token string `json:"token"`
}

// Cuerpo de mensaje register (solicitud)
type RegisterMsgReqBody UserPayload

// Cuerpo de mensaje register (respuesta)
type RegisterMsgResBody struct {
	User User `json:"user"`
}

// Cuerpo de mensaje whoami (solicitud)
type WhoamiMsgReqBody struct {
	Token string `json:"token"`
}

// Cuerpo de mensaje whoami (respuesta)
type WhoamiMsgResBody struct {
	User User `json:"user"`
}

// Cuerpo de mensaje whois (solicitud)
type WhoisMsgReqBody struct {
	// Token de sesion de un usuario autorizado
	Token string `json:"token"`
	// Id de usuario del que se quiere obtener infomacion
	UserID int `json:"user_id"`
}

// Cuerpo de mensaje whois (respuesta)
type WhoisMsgResBody struct {
	User User `json:"user"`
}

// Cuerpo de mensaje shout (solicitud)
type ShoutMsgReqBody struct {
	Token   string `json:"token"`   // Necesario para autenticar el usuario al que se hace referencia en los claims del jwt
	Message string `json:"message"` // Contenido de mensaje a registrar
}

// Cuerpo de mensaje shout (respuesta)
type ShoutMsgResBody struct {
	Owner   int    `json:"owner"`
	Message string `json:"message"`
}

// Cuerpo de mensaje guest (solicitud & respuesta).
type GuestMsgBody struct {
	Message string `json:"message"`
}

// Tipos relacionados con sistema de balanceo de carga ------

// Representacion de un servidor websocket
type WSServer struct {
	Type int    `json:"type"`
	IP   string `json:"ip"`
	Port string `json:"port"`
}

func (wss WSServer) BuildAddress() string {
	return fmt.Sprintf("%s:%s", wss.IP, wss.Port)
}

func (wss WSServer) BuildWSConnectionURL() string {
	return fmt.Sprintf("ws://%s/ws", wss.BuildAddress())
}

// Tipos de errores genericos ------

type ErrorWhileOpeningFile struct {
	Message string `json:"message"`
}

func (e ErrorWhileOpeningFile) Error() string {
	return fmt.Sprintf("ErrorWhileOpeningFile: %s", e.Message)
}

type ErrorWhileClosingFile struct {
	Message string `json:"message"`
}

func (e ErrorWhileClosingFile) Error() string {
	return fmt.Sprintf("ErrorWhileClosingFile: %s", e.Message)
}

type ErrorWhileRemovingFile struct {
	Message string `json:"message"`
}

func (e ErrorWhileRemovingFile) Error() string {
	return fmt.Sprintf("ErrorWhileRemovingFile: %s", e.Message)
}

type UnauthorizedUserError struct{}

var UnauthUserErr = UnauthorizedUserError{}

func (e UnauthorizedUserError) Error() string {
	return "UnauthorizedUserError: user asociated to token is not authorized"
}

// Tipos de errores relacionados con el lockfile (mecanica de evitar varias instancias del programa al mismo tiempo) ------

// Error retornado por la funcion `PreventRunningMultipleTimes` en caso de no poder desbloquer el lockfile.
type ErrorDueUnlockingLockfile struct {
	Message string `json:"message"`
}

func (e ErrorDueUnlockingLockfile) Error() string {
	return fmt.Sprintf("ErrroDueUnlockingLockfile: %s", e.Message)
}

// Error retornado por la funcion `PreventRunningMultipleTimes` en caso de que existen multiples instancias del programa al mismo tiempo
type ErrorForSeveralProcessInstances struct {
	Message string `json:"message"`
}

func (e ErrorForSeveralProcessInstances) Error() string {
	return fmt.Sprintf("ErrorForSeveralProcessInstances: %s", e.Message)
}

// Tipos de errores relacionados con WSServers

type ErrorConnectingWithWSServer struct {
	Message  string   `json:"message"`
	WSServer WSServer `json:"ws_server"`
}

func (e ErrorConnectingWithWSServer) Error() string {
	wssBytes, _ := json.Marshal(e.WSServer)
	return fmt.Sprintf("ErrorConnectingWithWSServer: %s; wsserver: %s", e.Message, string(wssBytes))
}

type InvalidMessageBodyError struct{}

func (e InvalidMessageBodyError) Error() string {
	return "InvalidMessageBodyError: invalid message body type"
}

var InvalidMsgBodyErr = InvalidMessageBodyError{}

// Tipos relacionados con la base de datos ------

type DBConnInfo interface {
	GetConnectionURL() string
}

type PostgresConnInfo struct {
	Host         string
	Port         string
	DatabaseName string
	Username     string
	Password     string
}

// Configuracion general para servidor ------

var WSServerTypes = map[string]int{
	"master": 0,
	"slave":  1,
}

// Es importante configurar independieme cada servidor para que funcione el cluster de servidores.
var Config = map[string]any{
	"defaultPort": "3000",
	"dbHost":      "localhost", // IP de red NAT
	"dbPort":      "5432",      // Puerto predeterminado de postgres
	"dbName":      "gowsauthv2",

	// Credenciales de la base de datos (modo desarrollo)
	"dbUsername": "postgres", // Usuario predeterminado
	"dbPassword": "root",

	"wsServerType": WSServerTypes["master"],
}

// Constantes y variables globales ------

var WSServers = []WSServer{
	{
		Type: WSServerTypes["master"],
		IP:   "localhost",
		Port: "3000",
	},
	// {
	// 	Type: WSServerTypes["slave"],
	// 	IP:   "192.168.1.3",
	// 	Port: "3000",
	// },
}

// Secreto para los jsonwebtokens (modo desarrollo)
const Secret = "aGVsbG8gd29ybGQ="

// Tipos de WSMessages
var MessageTypes = map[string]int{
	"shout":    0,
	"users":    1,
	"messages": 2,
	"whoami":   3,
	"whois":    4,
	"login":    5,
	"register": 6,
	"weight":   7,
	"error":    8,
}

// Slice de conexiones websocket
var Connections = []*websocket.Conn{}

// Funciones de utilidades genericas

/*
Funcion para comparar los int a los que apuntan los punteros del slice proporcionado como parametro. En caso de error la funcion retornara -1. Algunas situaciones donde la funcion retorna -1 son:

1. Cuando todos los punteros sean nil

2. Si la longitud del slice es inferior a 1
*/
func GetIndexOfMinorIntPointer(numbers []*int) int {
	if len(numbers) < 1 {
		return -1
	}
	lowerPointer := numbers[0]
	for _, nPointer := range numbers {
		if nPointer == nil {
			continue
		}
		if lowerPointer == nil {
			lowerPointer = nPointer
			continue
		}
		n := *nPointer
		lower := *lowerPointer
		if n < lower {
			lowerPointer = nPointer
		}
	}
	if lowerPointer == nil {
		return -1
	}
	lower := *lowerPointer

	// Obtiene el indice del puntero de int menor dentro del slice de numeros pasado como parametro
	indexOfLower := -1
	for i, eachNumber := range numbers {
		if *eachNumber == lower {
			indexOfLower = i
		}
	}

	return indexOfLower
}

// Funcion encargada de asegurarse de que el programa se ejecuta una sola vez por maquina (o por lo menos en un mismo interfaz, en caso de haber varios en la misma maquina). Esto previene problemas a la hora de identificar a un servidor websocket maestro por IP en el upgrader de los servidores esclavos.
func Lock(servicePort string, lockfilePath string, c chan struct{}) {
	// Abrir el lockfile
	lockFile, err := os.OpenFile(lockfilePath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		panic(ErrorWhileOpeningFile{err.Error()})
	}

	// Bloquer el lockfile
	processURL := WSServer{IP: "localhost", Port: servicePort}.BuildWSConnectionURL()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		panic(ErrorForSeveralProcessInstances{fmt.Sprintf("there is already an instance of this process running at %s", processURL)})
	}

	<-c // Cuando se termine de leer el canal (cuya informacion no tiene interes intrinseco)
	close(c)

	// Desbloquear el lockfile
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN); err != nil {
		panic(ErrorDueUnlockingLockfile{err.Error()})
	}
	// Cerrar el archivo lockfile
	if err := lockFile.Close(); err != nil {
		panic(ErrorWhileClosingFile{err.Error()})
	}
	// Borrar el archivo lockfile
	if err := os.Remove(lockfilePath); err != nil {
		panic(ErrorWhileRemovingFile{err.Error()})
	}
}

// Funciones relacionadas con los usuarios ------

func (p *UserPayload) HashPassword() error {
	hash, err := bcrypt.GenerateFromPassword([]byte(p.Password), 16)
	if err != nil {
		return err
	}
	p.Password = string(hash)
	return nil
}

// func VerifyPassword(hash string, password string) bool {
// 	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
// 		return false
// 	}
// 	return true
// }

func (p JwtPayload) NewToken(secret string) (string, error) {
	newP := jwt.Payload{
		"UserID": p.UserID,
	}
	token, err := newP.SignWithHS256(secret)
	if err != nil {
		return "", err
	}
	return token, nil
}

// Funcion verificadora de token (asi como del usuario asociado a dicho token)
func VerifyToken(db *sql.DB, secret string, t string) (*JwtPayload, error) {
	rawP, err := jwt.VerifyWithHS256(secret, t)
	if err != nil {
		return nil, err
	}
	pBytes, err := json.Marshal(rawP)
	if err != nil {
		return nil, err
	}
	var p JwtPayload
	if err := json.Unmarshal(pBytes, &p); err != nil {
		return nil, err
	}
	// Tras verificar el token se comprueba que este apunte a un usuario existente
	user, err := GetUserById(db, p.UserID)
	if err != nil && user == nil {
		return nil, err
	}
	return &p, nil
}

/*
status, token, err := AuthenticateUser(db, c)

status == 0 - err == nil

status == 1 - err.Error() == {Username: xx, Password: xx} invalid credentials

status == 2 - err.Error() == internal server error
*/
func AuthenticateUser(db *sql.DB, c LoginMsgReqBody) (int, string, error) {
	query :=
		`
	SELECT * FROM users WHERE username = $1 AND crypt($2, password) = password;
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
	// Comprobacion basica de los campos del userpayload
	if strings.Trim(p.Username, " ") == "" {
		return fmt.Errorf("invalid username for new user")
	} else if strings.Trim(p.Password, " ") == "" {
		return fmt.Errorf("invalid password for new user")
	} else if strings.Trim(p.Firstname, " ") == "" {
		return fmt.Errorf("invalid firstname for new user")
	} else if strings.Trim(p.Lastname, " ") == "" {
		return fmt.Errorf("invalid lastname for new user")
	}

	_, err := GetUserByUsername(db, p.Username)
	if err == nil {
		return fmt.Errorf("username for new user is already taken")
	}

	// Insertar nuevo usuario
	query :=
		`
	INSERT INTO users (username, password, firstname, lastname, admin) VALUES ($1, crypt($2, gen_salt('bf')), $3, $4, $5)
	`
	if _, err := db.Exec(query, p.Username, p.Password, p.Firstname, p.Lastname, p.Admin); err != nil {
		return err
	}
	return nil
}

func GetUserByUsername(db *sql.DB, u string) (*User, error) {
	query :=
		`
	SELECT * FROM users WHERE username = $1
	`
	row := db.QueryRow(query, u)
	var (
		userID int
		username,
		password,
		firstname,
		lastname string
		admin bool
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
	SELECT * FROM users WHERE user_id = $1
	`
	row := db.QueryRow(query, id)
	var (
		userID int
		username,
		password,
		firstname,
		lastname string
		admin bool
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
	rows, err := db.Query(query)
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
			admin bool
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

// Funcion constructora para mensajes de error
func NewErrorMessage(errBody string) WSMessage {
	return WSMessage{
		Type: MessageTypes["error"],
		Body: ErrorMsgBody{
			Error: errBody,
		},
	}
}

// Funcion encargada de guardar mensajes en la base de datos
func SaveMessage(db *sql.DB, sRes ShoutMsgResBody) error {
	query :=
		`
	INSERT INTO messages (owner, message) VALUES ($1, $2)
	`
	_, err := db.Exec(query, sRes.Owner, sRes.Message)
	return err
}

// Funcion encargada de recoger todos los cuerpos de mensaje de tipo shout guardados en la base de datos
func GetAllMessages(db *sql.DB) ([]Message, error) {
	query :=
		`
	SELECT * FROM messages
	`
	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	messages := []Message{}
	for rows.Next() {
		var (
			messageID int
			owner     int
			message   string
		)
		if err := rows.Scan(&messageID, &owner, &message); err != nil {
			return nil, err
		}
		m := Message{
			MessageID: messageID,
			Owner:     owner,
			Message:   message,
		}
		messages = append(messages, m)
	}
	return messages, nil
}

// Utilidades de la base de datos ------

func (p PostgresConnInfo) GetConnectionURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", p.Username, p.Password, p.Host, p.Port, p.DatabaseName)
}

func Connect(connInfo DBConnInfo) (*sql.DB, error) {
	db, err := sql.Open("postgres", connInfo.GetConnectionURL())
	if err != nil {
		return nil, err
	}
	return db, nil
}

// Es necesario registrar la extension crypto de postgres para la validacion de la contraseña hasheada con la funcion crypto (y tambien la funcion gen_salt en caso de introducir un nuevo usuario en la base de datos)
func RegisterCryptoExtension(db *sql.DB) error {
	query :=
		`
	CREATE EXTENSION IF NOT EXISTS pgcrypto;
	`
	_, err := db.Exec(query)
	return err
}

// Utilidades websocket ------

var Upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		if Config["wsServerType"] == WSServerTypes["slave"] {
			// Es imposible que retorne un error porque al principio de la aplicacion se hace una comprobacion de la configuracion de los WSServers tirando un panic en caso de fallo
			masterWSServer, _ := GetMasterWSServer()
			rhost, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return false
			}
			return rhost == masterWSServer.IP
		}
		// Si el servidor es maestro entonces admide conexiones websocket desde cualquier sitio
		return true
	},
}

func GetMasterWSServer() (*WSServer, error) {
	masterWSServerCount := 0
	var wsServer *WSServer = nil
	var err error = nil
	for _, server := range WSServers {
		if server.Type == WSServerTypes["master"] {
			masterWSServerCount++
			if masterWSServerCount > 1 {
				err = fmt.Errorf("websocket clustering requires only one master websocket server")
				wsServer = nil
				break
			}
			wsServer = &server
		}
	}
	if err == nil && wsServer == nil {
		err = fmt.Errorf("one master websocket server is required for websocket clustering")
	}
	return wsServer, err
}

// Proporciona una conexion websocket con el servidor mas optimo en terminos de carga de trabajo (considerando como parametro de carga de trabajo el numero de conexiones websocket abiertas con dicho servidor)
func GetWSServerConnWithLessWorkload() (*websocket.Conn, error) {
	weights := []*int{}
	cliConnections := []*websocket.Conn{}
	for _, server := range WSServers {
		if server.Type == WSServerTypes["master"] {
			n := len(Connections)
			weights = append(weights, &n)
			cliConnections = append(cliConnections, nil)
			continue
		}

		cliConn, _, err := websocket.DefaultDialer.Dial(server.BuildWSConnectionURL(), nil)
		// En caso de error, no retornar. Al retornar se sobre cargaria el servidor maestro. Es preferible introducir un peso nil y tratar de obtener el mejor wsserver sin tener en cuenta el servidor que fallo.
		if err != nil {
			fmt.Println(err.Error())
			weights = append(weights, nil)
			cliConnections = append(cliConnections, nil)
			continue
		}
		cliConnections = append(cliConnections, cliConn)

		c := make(chan error)
		wg := sync.WaitGroup{}
		var weight int
		var chanErr error = nil

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cliConn.WriteJSON(WSMessage{
				Type: MessageTypes["weight"],
				Body: nil,
			}); err != nil {
				c <- err
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			var m WeigthMsgBody
			if err := cliConn.ReadJSON(&m); err != nil {
				c <- err
				return
			}
			weight = m.Weigth
		}()

		go func() {
			chanErr = <-c
			wg.Done() // si un error es enviado al canal, el contador del wait group debe bajar a cero para pasar el wait
		}()

		wg.Wait()
		close(c) // cerrar el canal cuando las dos goroutines terminen (o bien cuando un error se introduzca en el canal y por lo tanto se agregue otro punto al contador del waitgroup)

		if chanErr != nil {
			weights = append(weights, nil)
		} else {
			weights = append(weights, &weight)
		}
	}
	indexOfConnection := GetIndexOfMinorIntPointer(weights)
	if indexOfConnection == -1 {
		return nil, fmt.Errorf("error determining the most optimal connection for routing")
	}
	cliConn := cliConnections[indexOfConnection]
	// Cerrar todas las conexiones del slice menos la conexion optima
	for i, eachCliConn := range cliConnections {
		if i != indexOfConnection {
			eachCliConn.Close()
		}
	}
	return cliConn, nil
}

// Elimina la conexion del slice de conexiones y la cierra
func ClearConnection(conn *websocket.Conn) error {
	for i, eachConn := range Connections {
		if eachConn == conn {
			Connections = append((Connections)[:i], (Connections)[i+1:]...)
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
	DB *sql.DB
}

func (wsh WSHandler) Handle(conn *websocket.Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := ClearConnection(conn); err != nil {
				// En caso de que no se pueda cerrar la conexion se muestra el error
				fmt.Println(err)
			}
		}()
		for {
			var m WSMessage
			if err := conn.ReadJSON(&m); err != nil {
				fmt.Println(err)
				break
			}
			if m.Type == MessageTypes["shout"] {
				if body, ok := m.Body.(string); ok {
					var sReq ShoutMsgReqBody
					if err := json.Unmarshal([]byte(body), &sReq); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					if strings.Trim(sReq.Message, " ") == "" {
						if err := conn.WriteJSON(NewErrorMessage(InvalidMsgBodyErr.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					p, err := VerifyToken(wsh.DB, Secret, sReq.Token)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					sRes := ShoutMsgResBody{
						Owner:   p.UserID,
						Message: sReq.Message,
					}

					// Guardar message en la base de datos
					if err := SaveMessage(wsh.DB, sRes); err != nil {
						if err := conn.WriteJSON(err.Error()); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					// Enviar mensaje a todas las conexiones websocket
					for _, eachConn := range Connections {
						if err := eachConn.WriteJSON(WSMessage{
							Type: MessageTypes["shout"],
							Body: sRes,
						}); err != nil {
							fmt.Println(err)
						}
					}

					continue
				}
				if err := conn.WriteJSON(NewErrorMessage(InvalidMsgBodyErr.Error())); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == MessageTypes["users"] {
				if body, ok := m.Body.(string); ok {
					var uReq UsersMsgReqBody
					if err := json.Unmarshal([]byte(body), &uReq); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					// Comprobar que el usuario asociado al token tenga el valor true para el campo admin.
					p, err := VerifyToken(wsh.DB, Secret, uReq.Token)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					user, err := GetUserById(wsh.DB, p.UserID)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					if !user.Admin {
						if err := conn.WriteJSON(NewErrorMessage(UnauthUserErr.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					users, err := GetAllUsers(wsh.DB)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					uRes := UsersMsgResBody{
						Users: users,
					}
					if err := conn.WriteJSON(WSMessage{
						Type: MessageTypes["users"],
						Body: uRes,
					}); err != nil {
						fmt.Println(err)
						break
					}
					continue
				}
				if err := conn.WriteJSON(NewErrorMessage(InvalidMsgBodyErr.Error())); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == MessageTypes["messages"] {
				if m.Body == nil {
					messages, err := GetAllMessages(wsh.DB)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					if err := conn.WriteJSON(WSMessage{
						Type: MessageTypes["messages"],
						Body: MessagesMsgBody{
							Messages: messages,
						},
					}); err != nil {
						fmt.Println(err)
						break
					}
					continue
				}
				if err := conn.WriteJSON(NewErrorMessage(InvalidMsgBodyErr.Error())); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == MessageTypes["whoami"] {
				if body, ok := m.Body.(string); ok {
					var wReq WhoamiMsgReqBody
					if err := json.Unmarshal([]byte(body), &wReq); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					p, err := VerifyToken(wsh.DB, Secret, wReq.Token)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					user, err := GetUserById(wsh.DB, p.UserID)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					whoamiResMsg := WhoamiMsgResBody{
						User: *user,
					}
					resM := WSMessage{
						Type: MessageTypes["whoami"],
						Body: whoamiResMsg,
					}

					if err := conn.WriteJSON(resM); err != nil {
						fmt.Println(err)
						continue
					}
					continue
				}
				if err := conn.WriteJSON(NewErrorMessage(InvalidMsgBodyErr.Error())); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == MessageTypes["whois"] {
				if body, ok := m.Body.(string); ok {
					var whoisReq WhoisMsgReqBody
					if err := json.Unmarshal([]byte(body), &whoisReq); err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					p, err := VerifyToken(wsh.DB, Secret, whoisReq.Token)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}
					tokenUser, err := GetUserById(wsh.DB, p.UserID)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					if !tokenUser.Admin {
						if err := conn.WriteJSON(NewErrorMessage(UnauthUserErr.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					user, err := GetUserById(wsh.DB, whoisReq.UserID)
					if err != nil {
						if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
							fmt.Println(err)
							break
						}
						continue
					}

					resM := WSMessage{
						Type: MessageTypes["whois"],
						Body: WhoisMsgResBody{
							User: *user,
						},
					}

					if err := conn.WriteJSON(resM); err != nil {
						fmt.Println(err)
						break
					}

					continue
				}
				if err := conn.WriteJSON(NewErrorMessage(InvalidMsgBodyErr.Error())); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == MessageTypes["login"] {
				if body, ok := m.Body.(string); ok {
					var c LoginMsgReqBody
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
					resM := WSMessage{
						Type: MessageTypes["login"],
						Body: LoginMsgResBody{
							Token: token,
						},
					}
					if err := conn.WriteJSON(resM); err != nil {
						fmt.Println(err)
						break
					}
					continue
				}
				if err := conn.WriteJSON(NewErrorMessage(InvalidMsgBodyErr.Error())); err != nil {
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

					resM := WSMessage{
						Type: MessageTypes["register"],
						Body: RegisterMsgResBody{
							User: *user,
						},
					}
					if err := conn.WriteJSON(resM); err != nil {
						fmt.Println(err)
						break
					}
					continue
				}
				if err := conn.WriteJSON(NewErrorMessage(InvalidMsgBodyErr.Error())); err != nil {
					fmt.Println(err)
					break
				}
			} else if m.Type == MessageTypes["weight"] {
				n := len(Connections)
				wRes := WeigthMsgBody{
					Weigth: n,
				}
				if err := conn.WriteJSON(WSMessage{
					Type: MessageTypes["weight"],
					Body: wRes,
				}); err != nil {
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

// Middleware encargado del encaminamiento de mensajes
type WSMessageRouterMid struct {
	Next func(conn *websocket.Conn) http.HandlerFunc
}

func (m WSMessageRouterMid) Handle(conn *websocket.Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if Config["wsServerType"] != WSServerTypes["master"] {
			m.Next(conn).ServeHTTP(w, r)
			return
		}
		// Conexion con el servidor websocket esclavo
		slaveConn, err := GetWSServerConnWithLessWorkload()
		if err != nil {
			if err := conn.WriteJSON(NewErrorMessage(err.Error())); err != nil {
				fmt.Println(err)
				return
			}
			m.Next(conn).ServeHTTP(w, r)
			return
		}
		// Si el puntero de conexion con el esclavo es nil, significa que que la opcion mas optima no es re-encaminar el mensaje si no que el servidor maestro procese la peticion websocket.
		if slaveConn == nil {
			m.Next(conn).ServeHTTP(w, r)
			return
		}

		for {
			// Leer mensajes de la conexion websocket del cliente usuaro (cliente web)
			var cliReqMsg WSMessage
			if err := conn.ReadJSON(&cliReqMsg); err != nil {
				fmt.Println(err)
				break
			}
			// Re-encaminar mismo mensaje a la conexion con el servidor esclavo mas optimo
			c := make(chan error)
			wg := sync.WaitGroup{}
			var slaveResMsg WSMessage
			var chanErr error = nil

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := slaveConn.WriteJSON(cliReqMsg); err != nil {
					c <- err
				}
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := slaveConn.ReadJSON(&slaveResMsg); err != nil {
					c <- err
				}
			}()
			go func() {
				chanErr = <-c
				wg.Done()
			}()

			wg.Wait()
			close(c)

			// Si sucede un error leyendo o escribiendo en la conexion del esclavo, abandonar la idea de re-encaminamiento cerrando la conexion con el esclavo, enviando un mensaje informativo al cliente usuario (cliente web) y por ultimo pasar las riendas al siguiente middleware.
			if chanErr != nil {
				slaveConn.Close()
				if err := conn.WriteJSON(NewErrorMessage("routing of websocket messages was not possible, the master server will take over")); err != nil {
					fmt.Println(err)
					return
				}
				m.Next(conn).ServeHTTP(w, r)
				return
			}

			// Enviar mensaje de respuesta de la conexion con el servidor websocket esclavo a la conexion con el cliente usuario (cliente web)
			if err := conn.WriteJSON(slaveResMsg); err != nil {
				fmt.Println(err)
				return
			}
		}
	}
}

type UpgraderMid struct {
	Next func(conn *websocket.Conn) http.HandlerFunc
}

func (m UpgraderMid) Handle(conn *websocket.Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		newConn, err := Upgrader.Upgrade(w, r, nil)
		if err != nil {
			fmt.Println(err)
			return
		}
		// Agrega la nueva conexion websocker al slice de conexiones
		Connections = append(Connections, newConn)

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
	// Configuracion del servidor mediante parametros en la ejecucion del programa
	port, ok := Config["defaultPort"].(string)
	if !ok {
		fmt.Printf("value `%v` for configuracion parameter `defaultPort` is invalid\n", Config["defaultPort"])
		return
	}
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	// Canal responsable de desbloquear la ejecucion de nuevas instancias del programa
	unlocker := make(chan struct{})
	defer func() {
		unlocker <- struct{}{}
	}()
	// Bloqueador de instancias de programa
	go Lock(port, "./lockfile.lock", unlocker)

	_, ok = Config["wsServerType"].(int)
	if !ok {
		fmt.Printf("value `%v` for configuracion parameter `defaultPort` is invalid\n", Config["wsServerType"])
		return
	}
	var wsServerType string = "master"
	if Config["wsServerType"] == 1 {
		wsServerType = "slave"
	}
	if len(os.Args) > 2 {
		// En caso de que el usuario lo especifique a la hora de ejecutar el programa, puede indicar si el servidor se ejecutara como esclavo o maestro.
		wsServerType = os.Args[2]
		if wsServerType != "master" && wsServerType != "slave" {
			fmt.Printf("value `%v` for configuracion parameter `wsServerType` is invalid\n", wsServerType)
			return
		}
		Config["wsServerType"] = WSServerTypes[wsServerType]
	}

	// Comprobar que el cluster de servidores tenga un unico servidor maestro. De lo contrario tirara un panic.
	if masterWSServer, err := GetMasterWSServer(); err != nil || masterWSServer == nil {
		fmt.Println(err)
		return
	}

	dbHost, ok := Config["dbHost"].(string)
	if !ok || strings.Trim(dbHost, " ") == "" {
		fmt.Printf("value `%v` for configuracion parameter `dbHost` is invalid\n", Config["dbHost"])
		return
	}
	dbPort, ok := Config["dbPort"].(string)
	if !ok || strings.Trim(dbPort, " ") == "" {
		fmt.Printf("value `%v` for configuracion parameter `dbPort` is invalid\n", Config["dbPort"])
		return
	}
	dbName, ok := Config["dbName"].(string)
	if !ok || strings.Trim(dbName, " ") == "" {
		fmt.Printf("value `%v` for configuracion parameter `dbName` is invalid\n", Config["dbName"])
		return
	}
	dbUsername, ok := Config["dbUsername"].(string)
	if !ok || strings.Trim(dbUsername, " ") == "" {
		fmt.Printf("value `%v` for configuracion parameter `dbUsername` is invalid\n", Config["dbUsername"])
		return
	}
	dbPassword, ok := Config["dbPassword"].(string)
	if !ok || strings.Trim(dbPassword, " ") == "" {
		fmt.Printf("value `%v` for configuracion parameter `dbPassword` is invalid\n", Config["dbPassword"])
		return
	}

	connInfo := PostgresConnInfo{
		Host:         dbHost,
		Port:         dbPort,
		DatabaseName: dbName,
		Username:     dbUsername,
		Password:     dbPassword,
	}
	db, err := Connect(connInfo)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer db.Close()

	if err := RegisterCryptoExtension(db); err != nil {
		fmt.Println(err)
		return
	}

	wshandler := UpgraderMid{
		Next: func(conn *websocket.Conn) http.HandlerFunc {
			return DatabaseMid{
				DB: db,
				Next: func(conn *websocket.Conn) http.HandlerFunc {
					return WSMessageRouterMid{
						Next: func(conn *websocket.Conn) http.HandlerFunc {
							return WSHandler{
								DB: db,
							}.Handle(conn)
						},
					}.Handle(conn)
				},
			}.Handle(conn)
		},
	}

	http.HandleFunc("/ws", wshandler.Handle(nil))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./index.html")
	})
	fmt.Printf("server running on %s - %s\n", port, wsServerType)
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
		fmt.Println(err)
		return
	}
}
