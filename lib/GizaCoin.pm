package GizaCoin;
use Dancer ':syntax';
use Dancer::Plugin::REST;
use UUID::Tiny ':std';
use DB;
use MIME::Base64;
use Data::Dumper;
use JSON qw//;
use Crypt::Fernet;

prepare_serializer_for_format;

our $VERSION = '0.1';

get '/' => sub {
    #template 'index';
    redirect 'https://coolsdaq.co/';
};

post '/account/:id/transaction_request.:format' => sub {
    my $apikey = param 'apikey';
    my $from_id = params->{id};
    my $amount = param 'amount';
    my $to_id = param 'to';

    my $token = param 'token';

    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    DB::verify_user($from_id, $token) or return status_bad_request("invaild token");
    DB::has_user($to_id) or return status_bad_request("invaild to user");

    my $result = DB::transaction_lock($from_id, $amount);
    if ($result) {
        if ($result->{'error'}) {
            return status_bad_request($result->{'error'});
        } else {
            my $transaction_id = $result->{'transaction_id'};
            my $transaction_code = Crypt::Fernet::encrypt(setting('access-token-private-key'), $from_id.':'.$to_id.':'.$amount.':'.$transaction_id);
            return status_accepted({transaction_code => $transaction_code});
        }
    } else {
        return status_bad_request("Cannot get transaction code");
    }
};

post '/account/:id/transfer.:format' => sub {
    my $from_id = params->{id};
    my $to_id = param 'to';
    my $token = param 'token';
    my $transaction_code = param 'transaction_code';
    my $amount = param 'amount';

    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    DB::verify_user($from_id, $token) or return status_bad_request("invaild token");


    my $decrypt_code = Crypt::Fernet::decrypt(setting('access-token-private-key'), $transaction_code, setting('transaction_code_ttl'));
    if ($decrypt_code) {
        my ($fid, $tid, $amt, $tranid) = split /:/, $decrypt_code;
        ( $from_id eq $fid ) or status_bad_request('wrong transaction token : 1');
        ( $to_id eq $tid ) or status_bad_request('wrong transaction token : 2');
        ( $amount eq $amt ) or status_bad_request('wrong transaction token : 3');
        if (DB::verify_transaction_id($from_id, $tranid)) {
            #### FIXME
            my $result = DB::transfer($from_id, $to_id, $amount, $tranid, $portal_id, request->user_agent, request->remote_address);
            if ($result->{'error'}) {
                  return status_bad_request($result->{'error'});
            } else {
                  return status_accepted($result);
            }
        } else {
            return status_bad_request('wrong transaction token : 4');
        }
    } else {
        return status_bad_request('transaction code expired');
    }
};

post '/account/:id/cancel_transfer.:format' => sub {
    my $uid = params->{id};
    my $transaction_code = param 'transaction_code';

    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    my $token = param 'token';
    DB::verify_user($uid, $token) or return status_bad_request("invaild token");

    my $decrypt_code = Crypt::Fernet::decrypt(setting('access-token-private-key'), $transaction_code, setting('transaction_code_ttl'));
    if ($decrypt_code) {
        my ($fid, $tid, $amt, $tranid) = split /:/, $decrypt_code;
        ( $uid eq $fid ) or status_bad_request('wrong transaction token : 1');
        if (DB::verify_transaction_id($uid, $tranid)) {
            #### FIXME
            my $result = DB::unlock_transaction_lock($uid, $tranid);
            if ($result) {
                  return status_ok({message => 'OK'});
            } else {
                  return status_bad_request('unlock error');
            }
        } else {
            return status_bad_request('wrong transaction token : 4');
        }
    } else {
        return status_bad_request('transaction code expired');
    }

};

get '/account/:id/transaction.:format' => sub {
    my $uid = params->{id};

    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    my $token = param 'token';
    DB::verify_user($uid, $token) or return status_bad_request("invaild token");

    my $result = DB::get_transaction_history($uid);
    
    if ($result->{'error'}) {
        return status_bad_request($result->{'error'});
    } else {
        return status_accepted($result);
    }
};

get '/account/:id/balance.:format' => sub {
    my $uid = params->{id};

    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    #my $token = param 'token';
    #DB::verify_user($uid, $token) or return status_bad_request("invaild token");

    if ($uid eq 'None') {
        return status_bad_request("invaild uid");
    } else {
        my $result = DB::get_balance($uid);
        return status_accepted({uid => $uid, amount => $result->{'amount'}, hash => $result->{'gizacoin_hash'}});
    }
};

post '/account/register.:format' => sub {
    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");
    my $adminkey = param 'admin';
    if ($adminkey ne setting('admin-key')) {
        return status_bad_request("invaild command");
    }

    my $name = param 'name';
    my $email = param 'email';
    my $login = param 'login';
    my $json_data = param 'json_data';
    #my $uid = param 'uid';
    my $reference;    
    if ($json_data) {
        my $json_text = decode_base64($json_data);
        $reference = JSON::decode_json($json_text);
    } else {
        $reference = {};
    }
    $email or return status_bad_request('email is empty');
    $login or $login = $email;
    $name or $name = $email;
    $reference->{'login'} = $name;
    $reference->{'name'} = $name;
    $reference->{'email'} = $email;
    $reference->{'portal'} = $portal_id;
    $reference->{'agent'} = request->user_agent;
    $reference->{'ip'} = request->remote_address;

    #my $result = DB::register($login, $name, $email, $reference, $uid);
    my $result = DB::register($login, $name, $email, $reference);
    debug("register info: ". Dumper($result));
    if (defined $result) {
        if ($result->{'error'}) {
            return status_bad_request($result->{'error'});
        } else {
            return status_created($result);
        }
    } else {
        return status_bad_request("Cannot Register");
    }
 
}; 

post '/auth/activate.:format' => sub {
    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    my $login = param 'login';
    my $code = param 'code';
    my $result = DB::verify_activate_code($login, $code);

    if ($result) {
        return status_accepted($result);
    } else {
        return status_bad_request("invaild activate code");
    }

};

get '/gizacoin/total.:format' => sub {
    my $result = DB::get_total_gizacoin();
    return status_accepted({total => $result});
};

post '/account/bind/bigchat.:format' => sub {
    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    my $login = param 'login';
    my $code = param 'code';
    my $phone = param 'phone';
    my $result = DB::bind_bigchat($login, $code, $phone);
    if ($result->{'error'}) {
        return status_bad_request($result->{'error'});
    } else {
        #return status_accepted($result);
        my $key = Crypt::Fernet::encrypt(setting('access-token-private-key'), $result->{'uid'}.':'.$phone);
        return status_accepted({'key' => $key});
    }
};

get '/account/:id/genes.:format' => sub {
    my $uid = params->{id};

    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    #my $token = param 'token';
    #DB::verify_user($uid, $token) or return status_bad_request("invaild token");

    if ($uid eq 'None') {
        return status_bad_request("invaild uid");
    } else {
        return status_accepted(DB::get_all_genes($uid));
    }

};

get '/account/genes.:format' => sub {
    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    my $key = param 'key';
    my $phone = param 'phone';
    my $decrypt_code = Crypt::Fernet::decrypt(setting('access-token-private-key'), $key);
    $decrypt_code or return status_bad_request("invaild key");

    my ($uid, $key_phone) = split /:/, $decrypt_code;
    ( $key_phone eq $phone ) or return status_bad_request("invaild key");

    my $result = DB::get_genes($uid, $phone);
    return status_accepted($result);
};

post '/account/genes/update.:format' => sub {
    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    my $key = param 'key';
    my $amount = param 'amount';
    my $phone = param 'phone';

    my $decrypt_code = Crypt::Fernet::decrypt(setting('access-token-private-key'), $key);
    $decrypt_code or return status_bad_request("invaild key");
    
    my ($uid, $key_phone) = split /:/, $decrypt_code; 
    ( $key_phone eq $phone ) or return status_bad_request("invaild key");

    DB::update_genes($uid, $phone, $amount);

    return status_accepted({message => 'OK'});
};

get '/account/:id/activate_code.:format' => sub {
    my $uid = params->{id};
    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    my $token = param 'token';
    DB::verify_user($uid, $token) or return status_bad_request("invaild token");

    my $code = DB::get_activate_code($uid);
    return status_accepted({code => $code}); 
};

get '/account/:id/genes/activate_code.:format' => sub {
    my $uid = params->{id};
    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    my $token = param 'token';
    DB::verify_user($uid, $token) or return status_bad_request("invaild token");

    my $code = DB::get_app_activate_code($uid);
    return status_accepted({code => $code}); 
};

get '/app/:id/info.:format' => sub {
    my $appid = params->{id};
    my $result = DB::get_app_info($appid);
    if ($result) {
        return status_accepted($result);   
    } else {
        return status_bad_request('invalid app');
    }
};

post '/app/:id/auth.:format' => sub {
    my $appid = params->{id};

    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");
    my $key = param 'key';
    my $phone = param 'phone';
    my $ios = param 'appsig';

    my $decrypt_code = Crypt::Fernet::decrypt(setting('access-token-private-key'), $key);
    $decrypt_code or return status_bad_request("invaild key");

    my ($uid, $key_phone) = split /:/, $decrypt_code;
    ( $key_phone eq $phone ) or return status_bad_request("invaild key");

    my $app_detail = DB::get_app_info($appid);
    if (not $app_detail) {
        return status_bad_request('invalid app');
    }
 
    my $result = DB::get_appkey($uid, $appid, $key_phone);
    if ($ios and $ios eq 'iOS') {
        $result->{'urlScheme'} = $appid;
        $result->{'urlScheme'} =~ s/\.//g;
        $result->{'name'} = $app_detail->{'name'}
    }
    
    return status_accepted($result);

};

post '/app/:id/genes/update.:format' => sub {
    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    my $appid = params->{id};

    my $key = param 'key';
    my $amount = param 'amount';
    #my $phone = param 'phone';

    if (DB::verify_app_user($appid,$key)) {
    } else {
        return status_bad_request("invaild apikey");
    }

    my $decrypt_code = Crypt::Fernet::decrypt(setting('access-token-private-key'), $key);
    $decrypt_code or return status_bad_request("invaild key");

    my ($uid, $token, $key_phone, $key_appid) = split /:/, $decrypt_code;
    #( $key_phone eq $phone ) or return status_bad_request("invaild key");

    if (DB::update_app_genes($uid, $key_phone, $amount, $key_appid)) {
        return status_accepted({message => 'OK'});
    } else {
        return status_bad_request("update error");
    }
};

get '/phone/:phone/uid.:format' => sub {
    my $apikey = param 'apikey';
    $apikey or return status_bad_request("no apikey");
    my $portal_id = DB::verify_portal($apikey);
    $portal_id or return status_bad_request("invaild apikey");

    my $phone = params->{phone};
    my $result = DB::get_uid_by_phone($phone);
    if ($result) {
        return status_ok({uid => $result, phone => $phone}); 
    } else {
        return status_bad_request("no result");
    } 
};

true;
