# Rails with Devise and JSON Web Tokens
 ### Inspiration for this talk came from
 - [Deanin's FullStack Devise API walkthrough](https://youtu.be/PqizV5l1yFE)
 - Wanting to know more about JSON Web Tokens
 - Friends over at HackNotice
 - LEARN Academy

## Tools we will be using
  - Ruby
  - Rails
  - Devise
  - JSON Web Tokens
  - Postman


# A tiny bit about JWT - JSON Web Tokens
- pronouced Jot
- can be used for Authorization and Authentication in place of other formats like SAML
- Is a combination of three json objects that are hashed accroding to a specified algorithim sepreated by "."
- example
```
{
  "alg": "HS256",
  "typ": "JWT"
}.
{
  "sub": "1",
  "name": "Austin Walker",
  "jti": 1516239022
}.
rails_secrets_go_here
```
Would end up as...
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6IkF1c3RpbiBXYWxrZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.pnTJ07U-hnLG13WyPzkKfHE00rO5ybtDo6Z-HroXGHI
```
- This token is sent to the client via the Authorization headers as a bearer token
- For more infor checkout out [jwt](https://jwt.io/)
- A full list of claims that can be passed to the second object can be found [here](https://www.iana.org/assignments/jwt/jwt.xhtml#claims)
  - Note that if you send JWT tokens through HTTP headers, you should try to prevent them from getting too big. Some servers don't accept more than 8 KB in headers. If you are trying to embed too much information in a JWT token, like by including all the user's permissions, you may need an alternative solution.

# Creating a Rails Api app 
Creating a rails api is simple using the rails new command with the api flag. 
I also have some customizations on my rails new command where I am creating my rails application utilizing a postgresql database and dropping the native rails testing framework. 
```
√  $ rails new jwt_demo -d postgresql --api
√  $ cd jwt_demo
√  $ rails db:prepare
```
Prepare has a conditional that checks for a couple of different database / schema file situations and runs the appropriate commands.


## Installations
```
 $ bundle add devise devise-jwt rack-cors
```

## JwtDenylist Migrations
```
 $ rails generate devise:install
 $ rails generate devise User
 $ rails g model jwt_denylist jti:string exp:datetime
  <!-- For logging out users safely on individual devices -->
```
### Important
  - rename the migration file you just generated to be singular
  - rename the migration class you just generated to be singular
  - rename the migration create_table argument to be singular
```ruby
class CreateJwtDenylist < ActiveRecord::Migration[7.0]
  def change
    create_table :jwt_denylist do |t|
      t.string :jti, null: false
      t.datetime :exp, null: false

      t.timestamps
    end
    add_index :jwt_denylist, :jti
  end
end
```

```
 $rails db:migrate
```
## User Model
- Delete the second line in the user.rb model configuration 
- Add in the two lines below
- app/models/user.rb
```ruby
class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :jwt_authenticatable,
         jwt_revocation_strategy: JwtDenylist
end
```
## JWT Model
- /models/jwt_denylist.rb
```ruby
class JwtDenylist < ApplicationRecord
  include Devise::JWT::RevocationStrategies::Denylist

  self.table_name = 'jwt_denylist'
end
```


## Devise Controllers
- create file in controllers called members_controller
```ruby
class MembersController < ApplicationController
  before_action :authenticate_user!

  def show
    user = get_user_from_token
    render json: {
      message: "If you see this it's all working!",
      user: user
    }
  end

  private
  def get_user_from_token
    
    jwt_payload = JWT.decode(request.headers['Authorization'].split(' ')[1],
          Rails.application.credentials.devise[:jwt_secret_key]).first
    
    user_id = jwt_payload['sub']
    User.find(user_id.to_s)
  end
end
```
- create a folder in controllers called users  
  - create two files inside of this folder called 
    - registrations_controller.rb
    - sessions_controller.rb

app/controllers/users/registrations_controller.rb
```ruby
class Users::RegistrationsController < Devise::RegistrationsController
  respond_to :json

  def respond_with(resource, _opts = {})
    if resource.persisted?
      register_success
    else
      register_failure
    end
  end

  def register_success
    render json: {
      message: 'Well done you signed in successfully',
      user: current_user
    }, status: 200
  end

  def register_failure
    render json: {
      message: 'Registration was unsuccessful'
    }, status: 422
  end
end
```

app/controllers/users/sessions_controller.rb
```ruby
class Users::SessionsController < Devise::SessionsController
 respond_to :json

 private

  def respond_with(_resource, _opts = {})
    if current_user
    render json: {
      message: 'You are logged in.',
      user: current_user
    }, status: 200
    else
      render json: {
      message: 'Log in failed',
    }, status: 422
    end
  end

  def respond_to_on_destroy
    if current_user != nil
      log_out_failure
    else
      log_out_success
    end
  end

  def log_out_success
    render json: { message: 'You are logged out.' }, status: 200
  end

  def log_out_failure
    render json: { message: 'Hmm nothing happened.' }, status: 401
  end
end
```

## Devise configuration 
- config/initializers/devise.rb
- add this code inside the Devise setup do block, roughly line 18
```ruby
  config.jwt do |jwt|
    jwt.secret = Rails.application.credentials.devise[:jwt_secret_key]
  end
```
## Cookie Session Configuration
- set the session store to handle communication between browsers and server.
- [session_store article](https://api.rubyonrails.org/v6.0.3.3/classes/ActionDispatch/Session/CookieStore.html#method-c-new)
- config/application.rb
  - inster this code roughly around line 20
```ruby
 # This also configures session_options for use below
    config.session_store :cookie_store, key: '_interslice_session'

    # Required for all session management (regardless of session_store)
     config.middleware.use ActionDispatch::Cookies

     config.middleware.use config.session_store, config.session_options
```
## Generate a Secret Token
```
$ rake secret
```
- copy the code
```
$ EDITOR='code --wait' rails credentials:edit
```
- add the secret after jwt_secret_key:
``` 
secret_key_base: ...
devise: 
  jwt_secret_key: [cmd+v]

 ```
- SPECIAL NOTE: spaces and returns only, no tabs!
- Close the tab and you should see => File encrypted and saved.

## Devise Routes 
```ruby
devise_for :users,
  controllers: {
    sessions: 'users/sessions',
    registrations: 'users/registrations'
  }
get 'member-data', to: 'members#show'
```


# Cors

- config/initializers/cors.rb
```ruby
# Avoid CORS issues when API is called from the frontend app.
# Handle Cross-Origin Resource Sharing (CORS) in order to accept cross-origin AJAX requests.

# Read more: https://github.com/cyu/rack-cors

Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins '*'  # <- change this to allow requests from any domain while in development.

    resource '*',
      headers: :any,
      methods: [:get, :post, :put, :patch, :delete, :options, :head],
      expose: %w[Authorization Uid]
  end
end
```
# Postman
- Make sure to set your body settings to JSON
- Direct your postman to the POST/users endpoint  

POST to localhost:3000/users 
```JSON
{ 
    "user" : {
        "email": "test@example.com",
        "password" : "testing123",
        "password_confirmation" : "testing123"
    }
}
```
- After this action delete cookie in Postman by clicking cookie the the x by the interslice session. 
- This effectively works as logging out

- Direct your postman to the POST/users/sign_in endpoint. 

POST localhost:3000/users/sign_in
```JSON
{ 
    "user" : {
        "email": "test@example.com",
        "password" : "testing123"
    }
}
```
- Notice that when you log in that our API send back the current user's email and password
- If we look inside Headers -> Authorization -> Bearer we will find our JSON Web Token

- Direct your postman to the GET/member-data endpoint 
- and add the token from the previous respons to the authorization tab -> bearer token field.   

GET localhost:3000/member-data
```JSON
{ 
    "user" : {
        "email": "test@example.com",
        "password" : "testing123"
    }
}
```
Headers -> Authorization -> Bearer
- Direct your postman to the DELETE/users/sign_out endpoint 
- be sure to send over the token and the email. 

DELETE localhost:3000/users/sign_in
```JSON
{ 
    "user" : {
        "email": "test@example.com"
    }
}
```
And that's it!
