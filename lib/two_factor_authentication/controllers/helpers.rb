module TwoFactorAuthentication
  module Controllers
    module Helpers
      extend ActiveSupport::Concern

      included do
        before_action :handle_two_factor_authentication
      end

      private

      def handle_two_factor_authentication
        Devise.mappings.keys.flatten.any? do |scope|
          if !devise_controller?
            if enforce_2fa_at_signup?(scope)
              handle_two_factor_configuration(scope)
            elsif signed_in?(scope) and warden.session(scope)[TwoFactorAuthentication::NEED_AUTHENTICATION]
              handle_failed_second_factor(scope)
            end
          elsif restrict_2fa_bypass?(scope)
            handle_two_factor_configuration(scope)
          end
        end
      end

      def enforce_2fa_at_signup?(scope)
        ENV['ENFORCE_2FA_AT_SIGNUP'] == 'true' &&
        scope == :user && current_user &&
        !current_user.two_factor_enabled? &&
        current_user.sign_up_sf_account_first_time? &&
        !warden.session(scope)[:skip_two_factor_verification]
      end

      def restrict_2fa_bypass?(scope)
        ENV['ENFORCE_2FA_AT_SIGNUP'] == 'true' && scope == :user &&
        request.original_fullpath == user_two_factor_authentication_path &&
        current_user && !current_user.two_factor_enabled?
      end

      def handle_two_factor_configuration(scope)
        if request.format.present?
          if request.format.html?
            redirect_to configure_two_factor_auth_methods_path
          elsif request.format.json?
            render json: { redirect_to: configure_two_factor_auth_methods_path }, status: :unauthorized
          end
        else
          head :unauthorized
        end
      end

      def handle_failed_second_factor(scope)
        if request.format.present?
          if request.format.html?
            session["#{scope}_return_to"] = request.original_fullpath if request.get?
            redirect_to two_factor_authentication_path_for(scope)
          elsif request.format.json?
            session["#{scope}_return_to"] = root_path(format: :html)
            render json: { redirect_to: two_factor_authentication_path_for(scope) }, status: :unauthorized
          end
        else
          head :unauthorized
        end
      end

      def two_factor_authentication_path_for(resource_or_scope = nil)
        scope = Devise::Mapping.find_scope!(resource_or_scope)
        change_path = "#{scope}_two_factor_authentication_path"
        send(change_path)
      end

    end
  end
end

module Devise
  module Controllers
    module Helpers
      def is_fully_authenticated?
        !session["warden.user.user.session"].try(:[], TwoFactorAuthentication::NEED_AUTHENTICATION)
      end
    end
  end
end
