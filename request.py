import requests

def login(email, password):
    login_url = 'http://localhost:5000/login'
    payload = {
        'email': email,
        'password': password
    }

    response = requests.post(login_url, json=payload)
    response.raise_for_status()  # Raise an exception for any HTTP error

    data = response.json()
    access_token = data['access_token']
    refresh_token = data['refresh_token']
    print("access_token:", access_token)
    print("refresh_token", refresh_token)
    
    return access_token, refresh_token

def request_protected_endpoint(url, access_token):
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    response = requests.get(url, headers=headers)
    response.raise_for_status()  # Raise an exception for any HTTP error
    
    return response.json()

def main():
    email = 'control@vvfin.in'
    password = 'Pawan@2244'
    protected_url = 'http://localhost:5000/protected'

    try:
        access_token, refresh_token = login(email, password)
        protected_data = request_protected_endpoint(protected_url, access_token)
        
        # Process the response data from the protected endpoint
        print(protected_data)
    except requests.exceptions.RequestException as e:
        print('Error:', str(e))

if __name__ == '__main__':
    main()
