<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Hash;

class AuthController extends Controller
{
    public function register(Request $request){
        $validator = Validator::make($request->all(), [
            'name' => 'required|max:255',
            'email' => 'required|unique:users|max:255',
            'password' => 'required|min:6',
            'password_confirmation' => 'required|same:password|min:6',
        ]);
        if ($validator->fails()) {
            return response()->json([
                'message' => "Validation failed",
                'data' => $validator->errors(),
                'status' => 422
            ]);
        }
        $user=User::create([
            'name'=>$request->name,
            'email'=>$request->email,
            'password'=>Hash::make($request->password),
            'password_confirmation'=>Hash::make($request->password_confirmation)
        ]);

        $token  = $user->createToken('auth_token')->accessToken;

        return response([
            'token'=>$token
        ]);

    }

    public function login(Request $request){
        $validator = Validator::make($request->all(), [
            'email'=>'required',
            'password'=>'required|min:6'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'message' => "Validation failed",
                'data' => $validator->errors(),
                'status' => 422
            ]);
        }

        $user = User::where('email',$request->email)->first();

        if(!$user|| !Hash::check($request->password,$user->password)){
            return response([
                'message'=>'The provided credentials are incorrect',
                'status' => 422
            ]);
        }

        $token = $user->createToken('auth_token')->accessToken;

        return response([
            'token' => $token,
        ]);
    }

    public function logout(Request $request){
        if (Auth::check()) {
            Auth::user()->token()->revoke();
            return response()->json(['success' =>'Successfully logged out of application'],200);
        }else{
            return response()->json(['error' =>'api.something_went_wrong'], 500);
        }
    }
}
