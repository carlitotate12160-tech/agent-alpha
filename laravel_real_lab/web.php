<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider and all of them will be
| assigned to the "web" middleware group. Make something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});
// ── Agent-Alpha live-fire validation route ───────────────────────────────────
// Appended to routes/web.php at image build time. This route throws an
// uncaught exception on purpose. With APP_DEBUG=true Laravel renders the
// Ignition debug page, leaking the stack trace (Illuminate\ framework frames)
// and environment — exactly the info-leak Alpha's laravel_debug playbook keys
// on. With APP_DEBUG=false the same route returns a generic 500 with no leak.
Route::get('/trigger-error', function () {
    throw new RuntimeException('Intentional test exception for Agent-Alpha live-fire validation');
});

// ── Agent-Alpha: Whoops-style env table leak ─────────────────────────────────
// Renders env vars in <td>KEY</td><td>VALUE</td> format that laravel_env.py
// iter_env_leaks() parser expects (LARAVEL_ENV_TABLE_RE regex).
// This simulates the classic Laravel Whoops debug page env table that
// Laravel 9 and earlier rendered natively. Laravel 10+ uses Ignition
// (React-based) which does NOT render the env table in HTML, so we
// provide this explicit route for field-prove compatibility.
Route::get('/debug-env', function () {
    $envKeys = ["DB_USERNAME", "DB_PASSWORD", "DB_HOST", "DB_PORT", "DB_DATABASE", "APP_KEY", "APP_DEBUG", "REDIS_PASSWORD", "MAIL_PASSWORD"];
    $rows = "";
    foreach ($envKeys as $k) {
        $v = env($k, "");
        $rows .= "<tr><td>$k</td><td>$v</td></tr>";
    }
    return response("<!DOCTYPE html><html><head><title>Whoops! There was an error.</title></head><body><div class=\"exception\">Illuminate\\Database\\QueryException</div><h2>Environment Variables</h2><table>$rows</table><footer>Laravel v10.50.2 (PHP v8.2.31)</footer></body></html>", 500);
});
