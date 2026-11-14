<?php

namespace App\Actions\Fortify;

use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Laravel\Fortify\Http\Requests\LoginRequest;

class AuthenticateUser
{

    public function __invoke(LoginRequest $request)
    {
        $credentials = $request->only('email', 'password');
        $user = User::where('email', $credentials['email'])->first();
        if ($user) {
            $pepper = config('app.pepper');
            $passwordMatches = false;

            // Se l'utente ha un salt, utilizza il nuovo formato della password.
            if ($user->salt !== null) {
                $passwordWithSaltAndPepper = $credentials['password'] . $user->salt . $pepper;
                $passwordMatches = Hash::check($passwordWithSaltAndPepper, $user->password);
            } else {
                // Se il salt non esiste, verifica la password nel vecchio formato.
                $passwordMatches = Hash::check($credentials['password'], $user->password);
            }

            // Continua solo se la password inserita corrisponde all'hash salvato.
            if ($passwordMatches) {
                // Dopo un login corretto, aggiorna gli utenti al nuovo formato.
                if ($user->salt === null) {
                    $user->salt = Str::random(32);
                    $user->password = Hash::make($credentials['password'] . $user->salt . $pepper);
                    $user->save();
                }

                Auth::login($user);
                Log::info('User '.$user->email.' logged in at '.now().' from '.$request->ip());
                return $user;
            }
        }
        return null;
    }
}
