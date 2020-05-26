package middleware

import (
	"html/template"
	"log"
	"net/http"

	"github.com/gol4ng/httpware/v4/middleware"
)

const (
	unauthorizedName    = "unauthorized"
	unauthorizedContent = `<html>
<head><title>{{.Realm}} Unauthorize</title></head>
<body>
	<h1>Unauthorized access {{.Realm}} </h1>
	{{if .Debug}}<h2>{{.Error}}</h2>{{end}}
	<p><strong>This server could not verify that you are unauthorized to access the document requested. Either you supplied the wrong credential (e.g bad password), or your browser doesn't understand how to supply the credentials required.</strong></p>
	<hr>
</body>
</html>
`
)

var unauthorizedTemplate *template.Template

type unauthorizedData struct {
	Realm string
	Debug bool
	Error error
}

func init() {
	unauthorizedTemplate = template.Must(template.New(unauthorizedName).Parse(unauthorizedContent))
}

func BasicErrorHandler(realm string, debug bool) middleware.ErrorHandler {
	return func(err error, responseWriter http.ResponseWriter, req *http.Request) bool {
		responseWriter.Header().Add("WWW-Authenticate", "Basic realm=\""+realm+"\"")
		responseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
		responseWriter.Header().Set("X-Content-Type-Options", "nosniff")
		responseWriter.WriteHeader(http.StatusUnauthorized)
		executeErr := unauthorizedTemplate.ExecuteTemplate(responseWriter, unauthorizedName, unauthorizedData{
			Realm: realm,
			Debug: debug,
			Error: err,
		})
		if executeErr != nil {
			log.Print(executeErr)
		}
		return true
	}
}
