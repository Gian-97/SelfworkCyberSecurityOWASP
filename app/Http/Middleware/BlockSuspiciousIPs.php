<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Session;
use Symfony\Component\HttpFoundation\Response;

class BlockSuspiciousIPs
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */

    protected $maxAttempts = 5;
    protected $decayMinutes = 1;
    protected $blockMinutes = 1;

    public function handle(Request $request, Closure $next): Response
    {
        $ip = $request->ip();
        $key = $this->throttleKey($ip);

        if (Cache::has($key . ':blecked')) {
            Session::flash('errors', 'Il tuo IP è stato bloccato per attività sospette.');
            return redirect()->back();
        }

        if (Cache::has($key)) {
            $attempts = Cache::increment($key);
            if ($attempts > $this->maxAttempts) {
                Cache::put($key . ':blecked', true, $this->blockMinutes * 60);
                Log::warning("IP $ip bloccato per attività sospette.");
                Session::flash('errors', 'Il tuo IP è stato bloccato per attività sospette.');
                return redirect()->back();
            }
        } else {
            Cache::put($key, 1, $this->decayMinutes * 60);
        }
        return $next($request);
    }

    protected function throttleKey($ip)
    {
        return 'throttle:' . sha1($ip);
    }
}
