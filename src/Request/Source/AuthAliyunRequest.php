<?php


namespace JustAuth\Request\Source;


use pf\request\Request;
use JustAuth\Exception\AuthException;

class AuthAliyunRequest extends AuthCommonRequest
{
    /**
     *  获取授权跳转 执行重定向
     */
    public function authorization()
    {
        $auth_url = $this->source_url->authorize();
        $query    = array_filter([
            'response_type' => 'code',
            'client_id'     => $this->config['client_id'],
            'redirect_uri'  => $this->config['redirect_uri'],
            #'prompt'        => $this->config['prompt'] ?: 'admin_consent'
        ]);
        $url      = $auth_url . '?' . http_build_query($query);
        header('Location:' . $url);
        exit();
    }

    public function getAccessToken()
    {
        $token_url = $this->source_url->accessToken();
        $query     = array_filter([
            'client_id'     => $this->config['client_id'],
            'code'          => Request::get('code'),
            'grant_type'    => 'authorization_code',
            'client_secret' => $this->config['client_secret'],
            'redirect_uri'  => $this->config['redirect_uri'],
        ]);
        try {
            $result = $this->http->request('POST', $token_url, [
                'query' => $query,
            ]);
            return $result->getBody()->getContents();
        } catch (\Exception $e) {
            throw new AuthException($e->getCode(), $e->getMessage());
        }
    }

    public function getUserInfo($access_token)
    {
        $access_data = json_decode($access_token);
        $user_info_url = $this->source_url->userInfo();
        $query         = array_filter([
            'access_token' => $access_data->access_token
        ]);
        return json_decode($this->http->request('GET', $user_info_url, [
            'query' => $query,
        ])->getBody()->getContents(),true);
    }
}