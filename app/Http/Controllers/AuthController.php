<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Response;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller {

	public function signin(Request $request) {
		$credentials = $request->only('email', 'password');
		$user = User::where('email', $credentials['email'])->first();

		if (!is_null($user)) {
			$user_id = $user->id;

			if ($user->estado_id == 1) {
				if (!$token = JWTAuth::attempt($credentials)) {
					$data['errors'] = trans('request.failure.status');
					$data['msg'] = 'Usuario o contraseña incorrecta';
					$status = trans('request.failure.code.forbidden');
				} else {
					$data['msg'] = compact('token', 'user_id');
					$status = trans('request.success.code');
				}
			} else {
				$data['errors'] = trans('request.failure.status');
				$data['msg'] = 'Su cuenta se encuentra inactiva';
				$status = trans('request.failure.code.forbidden');
			}
		} else {
			$data['errors'] = trans('request.failure.status');
			$data['msg'] = trans('request.failure.bad');
			$status = trans('request.failure.code.not_founded');
		}
		return Response::json($data, $status);
	}

	public function logout(Request $request) {
		if ($request->has('token')) {
			try {
				JWTAuth::invalidate($request->token);

				$data['errors'] = false;
				$data['msg'] = 'su sesion ha finalizado';
				$status = trans('request.failure.code.forbidden');
			} catch (JWTException $e) {
				$data['errors'] = trans('request.failure.status');
				$data['msg'] = 'Algo ha fallado, intente nuevamente';
				$status = trans('request.failure.code.forbidden'); // 500
			}
		} else {
			$data['errors'] = trans('request.failure.status');
			$data['msg'] = 'Token requerido';
			$status = trans('request.failure.code.not_founded');
		}
		return Response::json($data, $status);
	}
}