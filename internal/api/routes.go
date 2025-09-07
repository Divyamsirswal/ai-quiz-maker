package api

import "github.com/gin-gonic/gin"

func SetupRoutes(router *gin.Engine) {
	api := router.Group("/api/v1")
	{
		users := api.Group("/users")
		{
			users.POST("/register", RegisterUser)
			users.POST("/login", Login)
		}
		api.GET("/quizzes/:id", GetQuiz)

		private := api.Group("/")
		private.Use(AuthMiddleware())
		{
			quizzes := private.Group("/quizzes")
			{
				quizzes.POST("", CreateQuiz)
				quizzes.POST("/:id/submit", SubmitQuiz)
			}
			private.GET("/attempts", GetMyAttempts)
		}
	}
}
