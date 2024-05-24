<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Validator;
use App\Models\User;
use PhpParser\Node\Stmt\TryCatch;
use Tymon\JwTAuth\Contracts\JWTSubject;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (!$token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        $data = [
            'sub' => auth('api')->user()->id,
            'random' => rand() . time(),
            'exp' => time() + config('jwt.refresh_ttl')
        ];

        $refresh_token = JWTAuth::getJWTProvider()->encode($data);

        return $this->respondWithToken($token, $refresh_token);
    }

    public function signup()
    {
        // Nhận thông tin đăng ký từ yêu cầu HTTP
        $credentials = request(['name', 'email', 'password']);

        // Kiểm tra tính hợp lệ của thông tin đăng ký
        $validator = Validator::make($credentials, [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|unique:users|max:255',
            'password' => 'required|string|min:6|max:255',
        ]);

        // Nếu thông tin không hợp lệ, trả về lỗi
        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 422);
        }

        // Tạo một bản ghi mới trong bảng `users`
        $user = User::create([
            'name' => $credentials['name'],
            'email' => $credentials['email'],
            'password' => bcrypt($credentials['password']),
        ]);

        // Trả về một phản hồi thành công
        return response()->json(['message' => 'User registered successfully'], 201);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function profile()
    {
        return response()->json(auth('api')->user());
    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        $refresh_token = request()->refresh_token;
        try {
            $decode = JWTAuth::getJWTProvider()->decode($refresh_token);
            return response()->json($decode);
        } catch (JWTException $e) {
            return response()->json(['error' => 'Unauthorized'], 500);
        }
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token, $refreshToken)
    {
        /** @var Illuminate\Auth\AuthManager */
        $auth = auth();
        return response()->json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }
}
