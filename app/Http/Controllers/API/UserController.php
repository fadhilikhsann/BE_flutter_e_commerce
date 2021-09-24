<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;
use Illuminate\Support\Facades\Validator;
use Throwable;

class UserController extends Controller
{
    //
    public function register(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'name' => ['required', 'string', 'max:255'],
                'username' => ['required', 'string', 'max:255', 'unique:users'],
                'email' => ['required', 'string', 'max:255', 'email', 'unique:users'],
                'phone' => ['nullable', 'string', 'max:255'],
                'password' => ['required', 'string', new Password],
            ]);

            if ($validator->fails()) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ], 'Authentication Failed', 500);
            }

            User::create([
                'name' => $request->name,
                'username' => $request->username,
                'email' => $request->email,
                'phone' => $request->phone,
                'password' => md5($request->password),
            ]);

            $user = User::where('email', $request->email)->first();

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'User Registered');
        } catch (Exception $err) {
            //throw $th;
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' =>  $err
            ], 'Authentication Failed', 500);
        }
    }

    public function login(Request $request)
    {
        try {
            //code...
            $validator = Validator::make(
                $request->all(),
                [
                    'email' => ['required', 'string', 'max:255'],
                    'password' => ['required', 'string', 'max:255'],
                ]
            );

            if ($validator->fails()) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ], 'Authentication Failed', 500);
            }

            $user = User::where('email', $request->email)->first();

            if (md5($request->password) !== $user->password) {
                throw new Exception('Invalid credentials');
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user
            ], 'Authenticated');
        } catch (Exception $err) {
            //throw $th;
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $err
            ], 'Authentication Failed', 500);
        }
    }

    public function fetch(Request $request){
        return ResponseFormatter::success($request->user(),'Data profil user berhasil diambil');
    }

    public function updateProfile(Request $request){
        try {
            //code...

            $data = $request->all();
            $validator = Validator::make(
                $data,
                [
                    'name' => ['required', 'string', 'max:255'],
                    'username' => ['required', 'string', 'max:255', 'unique:users'],
                    'email' => ['required', 'string', 'max:255', 'email', 'unique:users'],
                    'phone' => ['nullable', 'string', 'max:255'],
                ]
            );
    
            if ($validator->fails()) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ], 'Authentication Failed', 500);
            }
    
            
    
            $user = Auth::user();
            $user->update($data);
    
            return ResponseFormatter::success(
                $user, 'Profile updated');
            

        } catch (Exception $err) {
            //throw $th;
            return ResponseFormatter::error([
                'message' => 'Something went wrong',
                'error' => $err
            ], 'Authentication Failed', 500);
        }
    }

    public function logout(Request $request){
        $token = $request->user()->currentAccessToken()->delete();
        return ResponseFormatter::success($token,'Token revoked');
    }
}
