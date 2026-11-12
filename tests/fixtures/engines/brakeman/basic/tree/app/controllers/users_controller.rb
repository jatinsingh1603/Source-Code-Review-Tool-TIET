class UsersController < ApplicationController
  def show
    @user = User.where("name = '#{params[:name]}'").first
  end
end
