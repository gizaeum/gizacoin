package DB;
use Dancer;
use DBI;
use DBD::Pg qw(:pg_types);
use UUID::Tiny ':std';
use Digest::MD5 qw(md5_hex);
use Data::Dumper;
use Encode;
use Crypt::Fernet;
use JSON qw//;
use String::MkPasswd qw(mkpasswd);
use Digest::SHA qw(sha512_hex);
use Cache::Memcached;
use String::Random;
binmode(STDOUT, ":utf8");

sub connect_mem {
  my $memcached = new Cache::Memcached {
    'servers' => ["127.0.0.1:11211"],
    'debug' => 0,
    'namespace' => 'gizacoin::',
    'compress_threshold' => 10_000,
  };

  return $memcached;
}

sub connect_db {
    #debug(Dumper("dbi:Pg:dgizacoinme=".setting('dgizacoinme').";host=".setting('dbhost').";port=".setting('dbport').";" . setting('dbuser'). "   ". setting('dbpasswd')));
    my $dbh = DBI->connect("dbi:Pg:dgizacoinme=".setting('dgizacoinme').";host=".setting('dbhost').";port=".setting('dbport').";", setting('dbuser'), setting('dbpasswd'));
    $dbh->{AutoCommit} = 1;
    $dbh->{RaiseError} = 1;
    $dbh->{pg_enable_utf8} = 1;
    return $dbh;
}

sub gen_code {
    my $pass = new String::Random;
    return $pass->randpattern("nnnnnn");
}

sub get_balance {
    my ($uid) = @_;
    #my $memcached = connect_mem();
    my $amount;# = $memcached->get('balance::'.$uid);
    my $hash;# = $memcached->get('balance-hash::'.$uid);
    my $out = {};

    if ($hash) {
        if ($amount) {
            $out->{'gizacoin_hash'} = $hash;
            $out->{'amount'} = $amount;
            return $out;
        }
    }

    my $dbh = connect_db();
    my $sql = 'SELECT amount, gizacoin_hash FROM balance where account_id = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($uid);
    my @result = $sth->fetchrow_array;
    $amount = $result[0];
    $hash = $result[1];
    
    $out->{'gizacoin_hash'} = $hash;
    $out->{'amount'} = $amount;
 
    #$memcached->set('balance::'.$uid, $amount, 86400);
    #$memcached->set('balance-hash::'.$uid, $hash, 86400);

    return $out;
}

sub get_transaction_history {
    my ($uid) = @_;
    my $dbh = connect_db();
    my $sql = 'SELECT transaction_id, from_id, to_id, amount, deduce, create_time AT TIME ZONE \'Etc/GMT+8\', reference FROM transaction where status = ? and (from_id = ? or to_id = ?) ORDER BY create_time DESC';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute('complete', $uid, $uid);

    my $out = {};
    my @history;
    while (my @result = $sth->fetchrow_array) {
        my $record = {};
        $record->{'transaction_id'} = $result[0];
        $record->{'from_id'} = $result[1];
        $record->{'to_id'} = $result[2];
        $record->{'amount'} = $result[3];
        $record->{'deduce'} = $result[4];
        $record->{'total'} = $result[3] + $result[4];
        $record->{'date'} = $result[5];
        my $reference = JSON::decode_json($result[6]);
        if ($uid eq $record->{'from_id'}) {
            $record->{'reference'} = $reference->{'detail'}->{'from'};
        } else {
            $record->{'reference'} = $reference->{'detail'}->{'to'};
        }
        #$record->{'reference'} = JSON::decode_json($result[6]);
        push @history, $record;
    }
    $out->{transactions} = \@history;
    return $out;

}

sub transaction_lock {
    my ($account_id, $amount) = @_;

    my $transaction_id = uuid_to_string(create_uuid(UUID_TIME));

    my $dbh = connect_db();

    my $out = {};

    $dbh->begin_work();

    my $sql = 'SELECT status from users WHERE uid = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($account_id);
    if ( $sth->err ) {
        $out->{'error'} = 'unknow error';
        $dbh->rollback();
        return $out;
    }
    my @result = $sth->fetchrow_array;
    if ((scalar @result) == 0) {
        $out->{'error'} = 'no such user';
        $dbh->rollback();
        return $out;
    }
    if ($result[0] eq 'lock') {
        $out->{'error'} = 'user locked, processing another transaction';
        $dbh->rollback();
        return $out;
    }

#    $sql = 'SELECT count(gizacoin_id) FROM gizacoin where account_id = ? and status = ?';
#    $sth = $dbh->prepare($sql);
#    $rv = $sth->execute($account_id, 'valid');
    $sql = 'SELECT amount, gizacoin_hash FROM balance where account_id = ?';
    $sth = $dbh->prepare($sql);
    $rv = $sth->execute($account_id);
    @result = $sth->fetchrow_array;
    my $total = $result[0];

    my $div = int($amount / 50);
    my $rem = int($amount % 50);
    my $deduce;
    if ($rem == 0) {
        $deduce = $div;
    } else {
        $deduce = $div + 1;
    }

    if ($total < $amount + $deduce) {
        debug("Not Enough Amount of $account_id, total = $total, amount = $amount, deduce = $deduce");
        $out->{'error'} = "ERROR: Not Enough Amount";
        return $out;
    }

    eval {
        $sql = 'INSERT INTO transaction_lock (account_id, transaction_id) VALUES (?, ?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($account_id, $transaction_id);
    };
    if ($@) {
        $dbh->rollback();
        $out->{'error'} = 'user locked, another transaction id occupied';
        return $out;
    }
    eval {
        $sql = 'UPDATE users SET status = ? WHERE uid = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute('lock', $account_id);
    };
    if ($@) {
        $dbh->rollback();
        $out->{'error'} = 'cannot lock user';
        return $out;
    }
    $dbh->commit();
    $out->{'transaction_id'} = $transaction_id;
    return $out;

}

sub unlock_transaction_lock {
    my ($account_id, $transaction_id) = @_;

    my $dbh = connect_db();
    $dbh->begin_work();

    my $sql = 'SELECT transaction_id FROM transaction_lock where account_id = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($account_id);
    my @result = $sth->fetchrow_array;
    if ((scalar @result) == 0) {
        $dbh->rollback();
        return 0;
    }

    if ($result[0] ne $transaction_id) {
        $dbh->rollback();
        return 0;
    }

    eval {
        $sql = 'UPDATE users SET status = ? WHERE uid = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute('enable', $account_id);
    };
    if ( $@ ) {
        $dbh->rollback();
        return 0;
    }

    eval {
        $sql = 'DELETE FROM transaction_lock WHERE account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($account_id);
    };
    if ( $@ ) {
        $dbh->rollback();
        return 0;
    }
    $dbh->commit();
    return 1;
}


sub super_unlock {
    my ($account_id) = @_;

    my $dbh = connect_db();

    $dbh->begin_work();
    my $sql;
    my $sth;
    my $rv;
    eval {
        $sql = 'UPDATE users SET status = ? WHERE uid = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute('enable', $account_id);
    };
    if ( $@ ) {
        $dbh->rollback();
        return 0;
    }

    eval {
        $sql = 'DELETE FROM transaction_lock WHERE account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($account_id);
    };
    if ( $@ ) {
        $dbh->rollback();
        return 0;
    }
    $dbh->commit();
    return 1;
}


sub transfer {
    my ($from_id, $to_id, $amount, $transaction_id, $portal, $agent, $ip) = @_;
    my $dbh = connect_db();

    #### FIXME
    $dbh->begin_work();

    my $reference = {};
    $reference->{'portal'} = $portal;
    $reference->{'agent'} = $agent;
    $reference->{'ip'} = $ip;
    
    my $sql;
    my $sth;
    my $rv;
    my $out = {};

    $sql = 'SELECT transaction_id FROM transaction_lock where account_id = ?';
    $sth = $dbh->prepare($sql);
    $rv = $sth->execute($from_id);
    my @result = $sth->fetchrow_array;
    if ((scalar @result) == 0) {
        $out->{'error'} = "wrong token";
        $dbh->rollback();
        return $out;
    }
    if ($result[0] ne $transaction_id) {
        $out->{'error'} = "wrong token";
        $dbh->rollback();
        return $out;
    }

    my $from_hash = uuid_to_string(create_uuid(UUID_TIME));
    my $to_hash = uuid_to_string(create_uuid(UUID_TIME));
    my $sys_hash = uuid_to_string(create_uuid(UUID_TIME));

    my $div = int($amount / 50);
    my $rem = int($amount % 50);
    my $deduce;
    if ($rem == 0) {
        $deduce = $div;
    } else {
        $deduce = $div + 1;
    }


############ New TMP
    eval {
        $sql = 'SELECT amount, gizacoin_hash FROM balance WHERE account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($from_id);
        my @org = $sth->fetchrow_array;
        my $from_total = $org[0];
        my $from_old_hash = $org[1];

        $sql = 'SELECT amount, gizacoin_hash FROM balance WHERE account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($to_id);
        @org = $sth->fetchrow_array;
        my $to_total = $org[0];
        my $to_old_hash = $org[1];

        $sql = 'SELECT amount, gizacoin_hash FROM balance WHERE account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute('88888888-8888-8888-8888-888888888888');
        @org = $sth->fetchrow_array;
        my $sys_total = $org[0];
        my $sys_old_hash = $org[1];


        my $from_value = $amount + $deduce;
        my $to_value = $amount;
        my $sys_value = $deduce; 

        $sql = 'UPDATE balance SET amount = amount - ?, gizacoin_hash = ?, last_update = CURRENT_TIMESTAMP where account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($from_value, $from_hash, $from_id);

        $sql = 'UPDATE balance SET amount = amount + ?, gizacoin_hash = ?, last_update = CURRENT_TIMESTAMP where account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($to_value, $to_hash, $to_id);

        $sql = 'UPDATE balance SET amount = amount + ?, gizacoin_hash = ?, last_update = CURRENT_TIMESTAMP where account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($sys_value, $sys_hash, '88888888-8888-8888-8888-888888888888');

        $sql = 'INSERT INTO gizacoin_hash_map (gizacoin_hash_id, amount, account_id) VALUES (?, ?, ?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($from_hash, $from_value, $from_id);

        $sql = 'INSERT INTO gizacoin_hash_map (gizacoin_hash_id, amount, account_id) VALUES (?, ?, ?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($to_hash, $to_value, $to_id);

        $sql = 'INSERT INTO gizacoin_hash_map (gizacoin_hash_id, amount, account_id) VALUES (?, ?, ?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($sys_hash, $sys_value, '88888888-8888-8888-8888-888888888888');

        my $detail = {};

        $from_value = $from_total - $amount - $deduce;
        $to_value = $to_total + $amount;
        $sys_value = $sys_total + $deduce;

        $detail->{'from'} = {'id' => $from_id, 'from_value' => $from_total, 'to_value' => $from_value, 'old_hash' => $from_old_hash, 'new_hash' => $from_hash};
        $detail->{'to'} = {'id' => $to_id, 'from_value' => $to_total, 'to_value' => $to_value, 'old_hash' => $to_old_hash, 'new_hash' => $to_hash};
        $detail->{'sys'} = {'from_value' => $sys_total, 'to_value' => $sys_value, 'old_hash' => $sys_old_hash, 'new_hash' => $sys_hash};
        $detail->{'amount'} = $amount;
        $detail->{'deduce'} = $deduce;
        $reference->{'detail'} = $detail;
    };
    if ($@) {
        $out->{'error'} = "transaction error during processing";
        $dbh->rollback();
        return $out;
    }

#########################

#    my @gizacoin_list;
#    eval {
#
#        $sql = 'SELECT gizacoin_id FROM gizacoin WHERE account_id = ? AND status = ? ORDER BY last_update ASC LIMIT ?';
#        $sth = $dbh->prepare($sql);
#        $rv = $sth->execute($from_id, 'valid', $amount);
#
#        my $sql2 = 'UPDATE gizacoin SET account_id = ? , last_update = CURRENT_TIMESTAMP where gizacoin_id = ?';
#
#
#        while (my @result = $sth->fetchrow_array) {
#            my $gizacoinid = $result[0];
#            my $sth2 = $dbh->prepare($sql2);
#            my $rv2 = $sth2->execute($to_id, $gizacoinid);
#            push @gizacoin_list, $gizacoinid;
#        }
#    }; 
#    if ( $@ ) {
#        $out->{'error'} = "transaction error during processing";
#        $dbh->rollback();
#        return $out;
#    }

# MOVE TO THE FRONT
#    my $div = int($amount / 50);
#    my $rem = int($amount % 50);
#    my $deduce;
#    if ($rem == 0) {
#        $deduce = $div;
#    } else {
#        $deduce = $div + 1;
#    }
#
#    my @decuce_list;
#    eval {
#        $sql = 'SELECT gizacoin_id FROM gizacoin WHERE account_id = ? AND status = ? ORDER BY last_update ASC LIMIT ?';
#        $sth = $dbh->prepare($sql);
#        $rv = $sth->execute($from_id, 'valid', $deduce);
#
#        my $sql2 = 'UPDATE gizacoin SET account_id = ? , last_update = CURRENT_TIMESTAMP where gizacoin_id = ?';
#
#
#        while (my @result = $sth->fetchrow_array) {
#            my $gizacoinid = $result[0];
#            my $sth2 = $dbh->prepare($sql2);
#            my $rv2 = $sth2->execute('88888888-8888-8888-8888-888888888888', $gizacoinid);
#            push @decuce_list, $gizacoinid;
#        }
#    };
#    if ( $@ ) {
#        $out->{'error'} = "transaction error during processing";
#        $dbh->rollback();
#        return $out;
#    }
# 
#    $reference->{'deduce_gizacoin'} = \@decuce_list;

    eval {
        $sql = 'INSERT INTO transaction (transaction_id, from_id, to_id, gizacoin_data, reference, status, amount, deduce) values (?, ?, ?, ?, ?, ?, ?, ?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($transaction_id, $from_id, $to_id, JSON::encode_json($reference), JSON::encode_json($reference), 'complete', $amount, $deduce);
        
    };
    if ($@) {
        $out->{'error'} = "transaction error during processing";
        $dbh->rollback();
        return $out;
    }


    eval {
        $sql = 'UPDATE users SET status = ? WHERE uid = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute('enable', $from_id);
    };
    if ( $@ ) {
        $out->{'error'} = "transaction error during processing";
        $dbh->rollback();
        return $out;
    }

    eval {
        $sql = 'DELETE FROM transaction_lock WHERE account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($from_id);
    };
    if ( $@ ) {
        $out->{'error'} = "transaction error during processing";
        $dbh->rollback();
        return $out;
    }
    $dbh->commit();

    #update_gizacoin_hash($from_id);
    #update_gizacoin_hash($to_id);

    $out->{'transaction_id'} = $transaction_id;
    $out->{'from_id'} = $from_id;
    $out->{'to_id'} = $to_id;
    $out->{'amount'} = $amount;
    $out->{'reference'} = $reference;

    #my $memcached = connect_mem();
    #$memcached->delete('balance::'.$from_id);
    #$memcached->delete('balance-hash::'.$from_id);    
    #$memcached->delete('balance::'.$to_id);
    #$memcached->delete('balance-hash::'.$to_id);    

    #$memcached->delete('balance::88888888-8888-8888-8888-888888888888');
    #$memcached->delete('balance-hash::88888888-8888-8888-8888-888888888888');

    return $out;
}

sub has_user {
    my ($uid) =@_;
    my $dbh = connect_db();
        my $sql = 'SELECT count(uid) FROM users WHERE uid = ?';
        my $sth = $dbh->prepare($sql);
        my $rv = $sth->execute($uid);
        my $count = $sth->fetchrow_array;
        if ($count > 0) {
            return 1;
        } else {
            return 0;
        }
}

sub verify_user {
    my ($uid, $token) = @_;
    # my $token = Crypt::Fernet::encrypt(setting('access-token-private-key'), $uid.':'.$result[0]);
    my $token_info = Crypt::Fernet::decrypt(setting('access-token-private-key'), $token);
    my ($accountid , $apikey) = split(/:/, $token_info);
    if ($uid ne $accountid) {
        return 0;
    } 
    my $dbh = connect_db();
    my $sql = 'SELECT count(account_id) FROM account_token WHERE account_id = ? AND token = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($accountid, $apikey);
    my $count = $sth->fetchrow_array;
    if ($count > 0) {
        return 1;
    } else {
        return 0;
    }
}

sub verify_portal {
    my ($api_token) = @_;
    my $token_info = Crypt::Fernet::decrypt(setting('access-token-private-key'), $api_token);
    my ($portal , $key) = split(/:/, $token_info);
    my $dbh = connect_db();
    my $sql = 'SELECT count(portal_token) FROM portal_token WHERE portal_id = ? AND token = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($portal, $key);
    my $count = $sth->fetchrow_array;
    if ($count > 0) {
        return $portal;
    } else {
        return;
    }
    
}

sub verify_transaction_id {
    my ($uid, $token) = @_;
    my $dbh = connect_db();
    my $sql = 'SELECT transaction_id FROM transaction_lock where account_id = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($uid);
    my @result = $sth->fetchrow_array;
    if ((scalar @result) == 0) {
        #$dbh->rollback();
        return 0;
    }

    if ($result[0] ne $token) {
        #$dbh->rollback();
        return 0;
    } else {
        return 1;
    }
    return 0;
}

sub verify_activate_code {
    my ($login, $code) = @_;
    my $dbh = connect_db();
    my $sql = 'SELECT count(code) FROM activate_code WHERE login = ? AND code = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($login, $code);
    my $count = $sth->fetchrow_array;
    if ($count > 0) {
        $sql = 'SELECT uid FROM users WHERE login = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($login);
        my @result = $sth->fetchrow_array;
        my $uid = $result[0];
        $sql = 'SELECT token FROM account_token WHERE account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid);
        my @result_1 = $sth->fetchrow_array;
        my $token = $result_1[0];
        $sql = 'SELECT token FROM account_token_revoke WHERE account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid);
        my @result_2 = $sth->fetchrow_array;
        my $revoke = $result_2[0];

        my $out = {};
        $out->{'uid'} = $uid;
        $out->{'token'} = Crypt::Fernet::encrypt(setting('access-token-private-key'), $uid.':'.$token);
        $out->{'revoke'} = Crypt::Fernet::encrypt(setting('access-token-private-key'), $uid.':'.$token.':'.$revoke);
        return $out;

    } else {
        return;
    }

}

sub bind_bigchat {
    my ($login, $code, $phone) = @_;
    my $dbh = connect_db();
    my $sql = 'SELECT count(code) FROM app_activate_code WHERE login = ? AND code = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($login, $code);
    my $count = $sth->fetchrow_array;
    if ($count > 0) {
        $sql = 'SELECT uid FROM users WHERE login = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($login);
        my @result = $sth->fetchrow_array;
        my $uid = $result[0];
        $sql = 'SELECT token FROM account_token WHERE account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid);
        my @result_1 = $sth->fetchrow_array;
        my $token = $result_1[0];
        $sql = 'SELECT token FROM account_token_revoke WHERE account_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid);
        my @result_2 = $sth->fetchrow_array;
        my $revoke = $result_2[0];

        my $out = {};
        $out->{'uid'} = $uid;
        $out->{'token'} = Crypt::Fernet::encrypt(setting('access-token-private-key'), $uid.':'.$token);
        $out->{'revoke'} = Crypt::Fernet::encrypt(setting('access-token-private-key'), $uid.':'.$token.':'.$revoke);

        $sql = 'DELETE FROM app_activate_code WHERE login = ? AND code = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($login, $code);


        eval {
            #$sql = 'UPDATE genes set account_id = ? where bigchat_id = ? AND app_id = ?';
            #$sth = $dbh->prepare($sql);
            #$rv = $sth->execute($uid, $phone, 'bigchat');

            $sql = 'INSERT INTO genes (account_id, bigchat_id) VALUES (?, ?)';
            $sth = $dbh->prepare($sql);
            $rv = $sth->execute($uid, $phone);
        };
        #return {error => 'already binded a bigchat account'} if ($@);
        if ($@) {
            #$sql = 'INSERT INTO genes (account_id, bigchat_id) VALUES (?, ?)';
            #$sth = $dbh->prepare($sql);
            #$rv = $sth->execute($uid, $phone);
            $sql = 'UPDATE genes set account_id = ? where bigchat_id = ? AND app_id = ?';
            $sth = $dbh->prepare($sql);
            $rv = $sth->execute($uid, $phone, 'bigchat');
        }
        eval {
            $sql = 'INSERT INTO new_genes (account_id) VALUES (?)';
            $sth = $dbh->prepare($sql);
            $rv = $sth->execute($uid);
        };

        return $out;

    } else {
        return {error => 'activation code not valid'};
    }
}

sub register {
    #my ($login, $name, $email, $json_ref, $uid) = @_;
    my ($login, $name, $email, $json_ref) = @_;
    my $dbh = connect_db();

    #$uid or $uid = uuid_to_string(create_uuid(UUID_TIME));
    my $uid = uuid_to_string(create_uuid(UUID_TIME));
    my $token = uuid_to_string(create_uuid(UUID_TIME));
    my $revoke = uuid_to_string(create_uuid(UUID_TIME));
    my $activate_code = gen_code(); #mkpasswd(-minspecial => 0, -minupper => 0);

    $dbh->begin_work();
    my $sql;
    my $sth;
    my $rv;

    my $out = {};

    eval {
        debug($uid, $login, $name, $email);
        $sql = 'INSERT INTO users (uid, login, name, email, reference) VALUES (?, ?, ?, ?, ?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid, $login, $name, $email, JSON::encode_json($json_ref));

    };
    if ( $@ ) {
        $dbh->rollback();
        $out->{'error'} = 'email used, user existed';
        return $out;
    }

    eval {
        $sql = 'INSERT INTO account_token (account_id, token) VALUES (?, ?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid, $token);

        $sql = 'INSERT INTO account_token_revoke (account_id, token) VALUES (?, ?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid, $revoke);

        $sql = 'INSERT INTO activate_code (login, code) VALUES (?, ?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($login, $activate_code);

        $sql = 'INSERT INTO balance (account_id, gizacoin_hash) VALUES (?,?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid, '88888888-8888-8888-8888-888888888888');
    };
    if ( $@ ) {
        $dbh->rollback();
        $out->{'error'} = 'create token error';
        return $out;
    }
    $dbh->commit();
    $out->{'uid'} = $uid;
    $out->{'token'} = Crypt::Fernet::encrypt(setting('access-token-private-key'), $uid.':'.$token);
    $out->{'revoke'} = Crypt::Fernet::encrypt(setting('access-token-private-key'), $uid.':'.$token.':'.$revoke);
    $out->{'login'} = $login;
    $out->{'activate_code'} = $activate_code;
    return $out;
}

#sub update_gizacoin_hash {
#    my ($uid) = @_;
#    my $dbh = connect_db();
#
#    my $sql = 'SELECT gizacoin_id FROM gizacoin WHERE account_id = ? AND status = ?';
#    my $sth = $dbh->prepare($sql);
#    my $rv = $sth->execute($uid, 'valid');
#
#    my @gizacoin_list;
#    while (my @result = $sth->fetchrow_array) {
#        my $gizacoinid = $result[0];
#        push @gizacoin_list, $gizacoinid;
#    }
#
#    my $sha = sha512_hex(@gizacoin_list);
#
#    eval {
#        $sql = 'UPDATE gizacoin_hash SET gizacoin_hash = ?, last_update = CURRENT_TIMESTAMP WHERE uid = ?';    
#        $sth = $dbh->prepare($sql);
#        $rv = $sth->execute($sha, $uid);
#    };
#    if ( $@ ) {
#        $sql = 'INSERT INTO gizacoin_hash (uid, gizacoin_hash) values (?, ?)';
#        $sth = $dbh->prepare($sql);
#        $rv = $sth->execute($uid, $sha);
#    }
#
#    $memcached->set('balance-hash::'.$uid, $sha, 86400);
#    return $sha; 
#}

sub get_total_gizacoin {
    #my $memcached = connect_mem();
    my $answer;# = $memcached->get('total-gizacoin');
    return $answer if $answer;

    my $dbh = connect_db();
    my $sql = 'SELECT SUM(amount) FROM balance where account_id <> ? and account_id <> ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute('88888888-8888-8888-8888-888888888888', '11111111-0000-1111-0000-111111111111');
    my $count = $sth->fetchrow_array;
    #$memcached->set('total-gizacoin', $count, 3600);
    return $count;
}

sub get_genes {
    my ($uid, $phone) = @_;
    my $dbh = connect_db(); 
    #my $sql = 'SELECT SUM(amount) FROM genes where account_id = ?';
    my $sql = 'SELECT amount, daily_amount FROM new_genes where account_id = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($uid);
    my @result = $sth->fetchrow_array;
    my $total = $result[0];
    my $amount = $result[1];
    
    return {'total' => $total, 'phone_amount' => $amount};
}

sub get_all_genes {
    my ($uid) = @_;
    my $dbh = connect_db();

    my $sql = 'SELECT amount, daily_amount FROM new_genes where account_id = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($uid);
    my @result = $sth->fetchrow_array;
    my $total = $result[0];
    my $amount = $result[0];
    my $daily = $result[1];

    $sql = 'SELECT amount, bigchat_id, daily_amount FROM genes where account_id = ?';
    $sth = $dbh->prepare($sql);
    $rv = $sth->execute($uid);

    my $out = {'total' => $total};
    my @all_rec;
    while (my @result = $sth->fetchrow_array) {
        my $data = {};
        $data->{'bigchat_id'} = $result[1];
        $data->{'amount'} = $amount;
        $data->{'daily_amount'} = $daily;
        push @all_rec, $data;
    }
    $out->{'accounts'} = \@all_rec;
    return $out;

}

sub update_genes {
    my ($uid, $phone, $amount, $app_id) = @_;
    $app_id or $app_id = 'bigchat';

    my $dbh = connect_db();

    #my $total = $amount;
    #my $sql = 'SELECT amount FROM genes where account_id = ? and bigchat_id = ?';
    #my $sth = $dbh->prepare($sql);
    #my $rv = $sth->execute($uid, $phone);
    #my $result = $sth->fetchrow_array;
    #$total += $result;
    my $sql;
    my $sth;
    my $rv;

    my $genes_daily_max = setting('genes-daily-max');

    eval {
        # old # $sql = 'UPDATE genes SET amount = ?, last_update = CURRENT_TIMESTAMP WHERE account_id = ? and bigchat_id = ?';
        # new # $sql = 'UPDATE genes SET daily_amount = LEAST(daily_amount + ?, ?), last_update = CURRENT_TIMESTAMP WHERE account_id = ? and bigchat_id = ? and app_id = ?';
        #$sql = 'update genes set daily_amount = LEAST(daily_amount + ?, ?), last_update = CURRENT_TIMESTAMP where app_id = \'bigchat\' and bigchat_id = (select bigchat_id from genes where account_id = ? limit 1);';
        $sql = 'update new_genes set daily_amount = LEAST(daily_amount + ?, ?), last_update = CURRENT_TIMESTAMP where account_id = ?';
        $sth = $dbh->prepare($sql);
        # new # $rv = $sth->execute($amount, $genes_daily_max, $uid, $phone, $app_id);
        $rv = $sth->execute($amount, $genes_daily_max, $uid);
    };
    if ($@) {
        #$sql = 'INSERT INTO genes (account_id, bigchat_id, amount) VALUES (?,?,?)';
        $sql = 'INSERT INTO new_genes (account_id, daily_amount) VALUES (?, LEAST(?,?))';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid, $amount, $genes_daily_max);
    }

    info("Add Genes: amount: $amount, uid: $uid, phone: $phone, appid: $app_id");
}

sub get_activate_code {
    my ($uid) = @_;

    my $dbh = connect_db();
    my $sql = 'select users.uid, users.login, activate_code.code from users join activate_code on users.login = activate_code.login where users.uid = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($uid);
    my $code;
    my $login;
    while (my @result = $sth->fetchrow_array) {
        $login = $result[1];
        $code = $result[2];
        last;
    }
    if ($code) {
        return $code;
    } else {
        eval {
            $code = gen_code(); #mkpasswd(-minspecial => 0, -minupper => 0);
            $sql = 'select login from users where uid = ?';
            $sth = $dbh->prepare($sql);
            $rv = $sth->execute($uid);
            my $login;
            while (my @result = $sth->fetchrow_array) {
                $login = $result[0];
                last;
            }
            $login or return;

            $sql = 'INSERT INTO activate_code (login, code) VALUES (?, ?)';
            $sth = $dbh->prepare($sql);
            $rv = $sth->execute($login, $code);
        };
        if ($@) {
            return;
        }
        return $code;
    }

}

sub get_app_activate_code {
    my ($uid) = @_;

    my $dbh = connect_db();
    my $sql = 'SELECT code FROM app_activate_code WHERE account_id = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($uid);
    my $code;
    while (my @result = $sth->fetchrow_array) {
        $code = $result[0]; 
        last;
    }
    if ($code) {
        return $code;
    } else {
        eval {
            $code = gen_code(); #mkpasswd(-minspecial => 0, -minupper => 0);
            $sql = 'select login from users where uid = ?';
            $sth = $dbh->prepare($sql);
            $rv = $sth->execute($uid);
            my $login;
            while (my @result = $sth->fetchrow_array) {
                $login = $result[0];
                last;
            }
            $login or return;

            $sql = 'INSERT INTO app_activate_code (account_id, login, code) VALUES (?, ?, ?)';
            $sth = $dbh->prepare($sql);
            $rv = $sth->execute($uid, $login, $code);
        }; 
        if ($@) {
            return;
        }
        return $code;
    }

}

sub verify_app_user {
    my ($appid, $token) = @_;
    # my $token = Crypt::Fernet::encrypt(setting('access-token-private-key'), $uid.':'.$result[0]);
    my $token_info = Crypt::Fernet::decrypt(setting('access-token-private-key'), $token);
    my ($accountid, $apikey, $phone, $en_appid) = split(/:/, $token_info);
    if ($appid ne $en_appid) {
        return 0;
    }
    my $dbh = connect_db();
    my $sql = 'SELECT count(account_id) FROM app_auth WHERE account_id = ? AND token = ? AND app_id = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($accountid, $apikey, $en_appid);
    my $count = $sth->fetchrow_array;
    if ($count > 0) {
        return 1;
    } else {
        return 0;
    }
}

sub get_appkey {
    my ($uid, $appid, $phone) = @_;
    my $token = uuid_to_string(create_uuid(UUID_TIME));
    my $dbh = connect_db();
    my $sql;
    my $sth;
    my $rv;
    eval {
        $sql = 'INSERT INTO app_auth(account_id, app_id, token) VALUES (?, ?, ?)';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid, $appid, $token);
    };
    if ($@) {
        $sql = 'SELECT token FROM app_auth WHERE account_id = ? AND app_id = ?';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid, $appid);
        my @result = $sth->fetchrow_array;
        $token = $result[0];
    }
    my $out = {};
    $out->{'token'} = Crypt::Fernet::encrypt(setting('access-token-private-key'), $uid.':'.$token.':'.$phone.':'.$appid);
    return $out;
}

sub get_app_info {
    my ($appid) = @_;
    my $dbh = connect_db();
    my $sql = 'select name, icon_url, info from apps where app_id = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($appid);
    my @result = $sth->fetchrow_array;
    my $out = {};
    $out->{'name'} = $result[0];
    $out->{'icon_url'} = $result[1];
    $out->{'info'} = $result[2];
    return $out;
}

sub update_app_genes {
    my ($uid, $phone, $amount, $app_id) = @_;
    $app_id or return 0;

    my $dbh = connect_db();

    #my $total = $amount;
    #my $sql = 'SELECT amount FROM genes where account_id = ? and bigchat_id = ?';
    #my $sth = $dbh->prepare($sql);
    #my $rv = $sth->execute($uid, $phone);
    #my $result = $sth->fetchrow_array;
    #$total += $result;
    my $sql;
    my $sth;
    my $rv;

    my $genes_daily_max = setting('genes-daily-max');

    #$sql = 'UPDATE genes SET amount = ?, last_update = CURRENT_TIMESTAMP WHERE account_id = ? and bigchat_id = ?';
    #$sql = 'UPDATE genes SET amount = amount + ?, last_update = CURRENT_TIMESTAMP WHERE account_id = ? and bigchat_id = ? and app_id = ?';
    #$sth = $dbh->prepare($sql);
    #$rv = $sth->execute($amount, $uid, $phone, $app_id);
    eval {
        $sql = 'update new_genes set daily_amount = LEAST(daily_amount + ?, ?), last_update = CURRENT_TIMESTAMP where account_id = ?;';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($amount, $genes_daily_max, $uid);
    };
    if ($@) {
        $sql = 'INSERT INTO new_genes (account_id, daily_amount) VALUES (?, LEAST(?,?))';
        $sth = $dbh->prepare($sql);
        $rv = $sth->execute($uid, $amount, $genes_daily_max);
    }

    info("Add Genes: amount: $amount, uid: $uid, phone: $phone, appid: $app_id");
    return 1;
}

sub get_uid_by_phone {
    my ($phone) = @_;
    my $dbh = connect_db();
    my $sql = 'select account_id from genes where bigchat_id = ? and app_id = ?';
    my $sth = $dbh->prepare($sql);
    my $rv = $sth->execute($phone, 'bigchat');
    my $uid;
    while (my @result = $sth->fetchrow_array) {
        $uid = $result[0];
        last;
    }
    if ($uid) {
        return $uid;
    } else {
        return;
    }
}
1;
