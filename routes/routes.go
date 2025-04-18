package routes

import (
	"example.com/goroutine/middleware"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(server *gin.Engine) {

	server.GET("/events", getEvents)    //GET,PUT......
	server.GET("/events/:id", getEvent) //dynamic path handler

	authenticated := server.Group("/")
	authenticated.Use(middleware.Authentication)
	authenticated.POST("/events",createEvent)
	authenticated.PUT("/events/:id", updateEvent)
	authenticated.DELETE("/events/:id", deleteEvent)
	authenticated.POST("/events/:id/register",registerForEvent)
	authenticated.DELETE("/events/:id/register",cancelRegistration)


	
	server.POST("/signup", signup)

	server.POST("/login", login)

}
