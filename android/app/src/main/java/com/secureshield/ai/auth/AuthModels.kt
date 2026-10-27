package com.secureshield.ai.auth

data class RegisterRequest(
    val email: String,
    val password: String,
    val full_name: String? = null
)

data class LoginRequest(
    val email: String,
    val password: String,
    val full_name: String? = null
)

data class GoogleAuthRequest(
    val email: String,
    val full_name: String? = null,
    val id_token: String? = null
)

data class UserResponse(
    val user_id: String,
    val email: String,
    val full_name: String,
    val provider: String,
    val db_file: String,
    val created_at: String,
    val last_login_at: String
)

data class AuthResponse(
    val status: String,
    val message: String,
    val token: String,
    val user: UserResponse
)
