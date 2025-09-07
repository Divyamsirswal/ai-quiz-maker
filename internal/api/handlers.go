package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Divyamsirswal/ai-quiz-maker/backend/internal/database"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wansatya/groq-go/pkg/groq"
	"golang.org/x/crypto/bcrypt"
)

type UserPayload struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type User struct {
	ID           string
	Email        string
	PasswordHash string
}

type CreateQuizPayload struct {
	Topic string `json:"topic" binding:"required"`
}

type AIQuestion struct {
	QuestionText  string   `json:"question_text"`
	Difficulty    string   `json:"difficulty"`
	Options       []string `json:"options"`
	CorrectAnswer string   `json:"correct_answer"`
}
type AIQuizResponse struct {
	Title     string       `json:"title"`
	Questions []AIQuestion `json:"questions"`
}

type OptionResponse struct {
	Text string `json:"text"`
}

type QuestionResponse struct {
	ID           string           `json:"id"`
	QuestionText string           `json:"question_text"`
	Difficulty   string           `json:"difficulty"`
	Options      []OptionResponse `json:"options"`
}

type QuizResponse struct {
	ID        string             `json:"id"`
	Title     string             `json:"title"`
	Topic     string             `json:"topic"`
	Questions []QuestionResponse `json:"questions"`
}

type QuizAttemptResponse struct {
	AttemptID      string    `json:"attemptId"`
	QuizID         string    `json:"quizId"`
	QuizTitle      string    `json:"quizTitle"`
	Score          int       `json:"score"`
	TotalQuestions int       `json:"totalQuestions"`
	CompletedAt    time.Time `json:"completedAt"`
}

type UserAnswer struct {
	QuestionID string `json:"questionId"`
	AnswerText string `json:"answerText"`
}

type SubmissionPayload struct {
	Answers []UserAnswer `json:"answers"`
}

type CorrectAnswer struct {
	QuestionID string
	Text       string
}

func RegisterUser(c *gin.Context) {
	var payload UserPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to hash password",
		})
		return
	}

	sql := `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`
	var userID string

	err = database.DB.QueryRow(context.Background(), sql, payload.Email, string(hashedPassword)).Scan(&userID)
	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == "23505" {
			c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"userId":  userID,
	})
}

func Login(c *gin.Context) {
	var payload UserPayload
	var user User

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	sql := `SELECT id, email, password_hash FROM users WHERE email = $1`
	err := database.DB.QueryRow(context.Background(), sql, payload.Email).Scan(&user.ID, &user.Email, &user.PasswordHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(payload.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
		"iat": time.Now().Unix(),
	})

	jwtSecret := os.Getenv("JWT_SECRET")
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func CreateQuiz(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
		return
	}

	var payload CreateQuizPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	apiKey := os.Getenv("GROQ_API_KEY")
	if apiKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "GROQ_API_KEY is not set"})
		return
	}

	client := groq.NewClient(apiKey)

	prompt := fmt.Sprintf(`
		Please create a quiz about "%s".
		The quiz should have a creative and engaging title.
		Generate exactly 6 questions: 2 easy, 2 medium, and 2 hard.
		For each question, provide 4 multiple-choice options. One of the options must be the correct answer.

		IMPORTANT: Respond with ONLY a valid JSON object. Do not include any text, explanation, or markdown before or after the JSON.
		The JSON object must follow this exact structure:
		{
			"title": "A Creative Title About the Topic",
			"questions": [
				{
					"question_text": "The text of the question?",
					"difficulty": "Easy",
					"options": ["Option A", "Option B", "Option C", "Correct Answer"],
					"correct_answer": "The text of the correct answer"
				}
			]
		}
	`, payload.Topic)

	req := groq.ChatCompletionRequest{
		Messages: []groq.Message{
			{Role: "user", Content: prompt},
		},
		Model: "llama-3.3-70b-versatile",
	}

	resp, err := client.CreateChatCompletion(context.Background(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to call Groq API"})
		return
	}

	if len(resp.Choices) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No response from Groq"})
		return
	}

	aiResponseContent := resp.Choices[0].Message.Content
	var aiQuiz AIQuizResponse
	if err := json.Unmarshal([]byte(aiResponseContent), &aiQuiz); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse AI response"})
		return
	}

	var newQuizID string
	tx, err := database.DB.Begin(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start database transaction"})
		return
	}
	defer tx.Rollback(context.Background())

	quizSQL := `INSERT INTO quizzes (title, topic, created_by) VALUES ($1, $2, $3) RETURNING id`
	err = tx.QueryRow(context.Background(), quizSQL, aiQuiz.Title, payload.Topic, userID).Scan(&newQuizID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save quiz to database"})
		return
	}

	for _, q := range aiQuiz.Questions {
		optionsForDB := make([]map[string]interface{}, len(q.Options))
		for i, opt := range q.Options {
			optionsForDB[i] = map[string]interface{}{
				"text":       opt,
				"is_correct": opt == q.CorrectAnswer,
			}
		}
		optionsJSON, _ := json.Marshal(optionsForDB)

		questionSQL := `INSERT INTO questions (quiz_id, question_text, difficulty, options) VALUES ($1, $2, $3, $4)`
		_, err = tx.Exec(context.Background(), questionSQL, newQuizID, q.QuestionText, q.Difficulty, optionsJSON)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save questions to database"})
			return
		}
	}

	if err := tx.Commit(context.Background()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Quiz created successfully!",
		"quizId":  newQuizID,
	})
}

func GetQuiz(c *gin.Context) {
	quizID := c.Param("id")

	var quiz QuizResponse
	quizSQL := `SELECT id, title, topic FROM quizzes WHERE id = $1`

	err := database.DB.QueryRow(context.Background(), quizSQL, quizID).Scan(&quiz.ID, &quiz.Title, &quiz.Topic)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Quiz not found"})
		return
	}

	questionsSQL := `SELECT id, question_text, difficulty, options FROM questions WHERE quiz_id = $1`
	rows, err := database.DB.Query(context.Background(), questionsSQL, quizID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch questions"})
		return
	}

	defer rows.Close()

	var questions []QuestionResponse

	for rows.Next() {
		var q QuestionResponse
		var optionsJSON []byte

		if err := rows.Scan(&q.ID, &q.QuestionText, &q.Difficulty, &optionsJSON); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan question row"})
			return
		}
		var dbOptions []map[string]interface{}
		if err := json.Unmarshal(optionsJSON, &dbOptions); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse question options"})
			return
		}

		q.Options = make([]OptionResponse, len(dbOptions))
		for i, opt := range dbOptions {
			q.Options[i] = OptionResponse{Text: opt["text"].(string)}
		}
		questions = append(questions, q)
	}
	quiz.Questions = questions
	c.JSON(http.StatusOK, quiz)
}

func SubmitQuiz(c *gin.Context) {
	quizID := c.Param("id")
	userID, _ := c.Get("userID")

	var payload SubmissionPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	sql := `
		SELECT 
			q.id, 
			opt.value ->> 'text' as correct_answer
		FROM 
			questions q,
			jsonb_array_elements(q.options) opt
		WHERE 
			q.quiz_id = $1 AND (opt.value ->> 'is_correct')::boolean = true;
	`
	rows, err := database.DB.Query(context.Background(), sql, quizID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch correct answers"})
		return
	}
	defer rows.Close()
	correctAnswers := make(map[string]string)
	for rows.Next() {
		var ca CorrectAnswer
		if err := rows.Scan(&ca.QuestionID, &ca.Text); err != nil {
			continue
		}
		correctAnswers[ca.QuestionID] = ca.Text
	}

	score := 0
	for _, userAnswer := range payload.Answers {
		if correctAnswerText, ok := correctAnswers[userAnswer.QuestionID]; ok {
			if userAnswer.AnswerText == correctAnswerText {
				score++
			}
		}
	}
	totalQuestions := len(correctAnswers)

	attemptSQL := `INSERT INTO quiz_attempts (user_id, quiz_id, score) VALUES ($1, $2, $3)`
	_, err = database.DB.Exec(context.Background(), attemptSQL, userID, quizID, score)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save quiz attempt"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":        "Quiz submitted successfully!",
		"score":          score,
		"totalQuestions": totalQuestions,
		"correctAnswers": correctAnswers,
		"userAnswers":    payload.Answers,
	})
}

func GetMyAttempts(c *gin.Context) {
	userID, _ := c.Get("userID")

	sql := `
		SELECT
			qa.id,
			qa.quiz_id,
			q.title,
			qa.score,
			(SELECT COUNT(*) FROM questions WHERE quiz_id = q.id) as total_questions,
			qa.completed_at
		FROM
			quiz_attempts qa
		JOIN
			quizzes q ON qa.quiz_id = q.id
		WHERE
			qa.user_id = $1
		ORDER BY
			qa.completed_at DESC;
	`

	rows, err := database.DB.Query(context.Background(), sql, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch quiz attempts"})
		return
	}
	defer rows.Close()

	var attempts []QuizAttemptResponse
	for rows.Next() {
		var attempt QuizAttemptResponse
		if err := rows.Scan(&attempt.AttemptID, &attempt.QuizID, &attempt.QuizTitle, &attempt.Score, &attempt.TotalQuestions, &attempt.CompletedAt); err != nil {
			log.Printf("Error scanning attempt row: %v", err)
			continue
		}
		attempts = append(attempts, attempt)
	}

	c.JSON(http.StatusOK, attempts)
}
