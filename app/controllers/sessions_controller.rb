class SessionsController < ApplicationController

  def create
    ### APPSEC Vuln 4: SQLi via parent class method with hash reassignment
    if user = User.find_by(email: get_email)
      render json: { token: user.token }
    else
      render json: { error: "Invalid email or password" }
    end
  end

  private

  def get_email
    params.require(:email)
  end
end