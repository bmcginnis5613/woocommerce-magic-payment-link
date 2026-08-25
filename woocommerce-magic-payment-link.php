<?php
/**
 * Plugin Name: WooCommerce Magic Payment Link
 * Description: Adds secure 30-day magic payment links to WooCommerce orders. A valid link signs in the customer attached to the order and lets WooCommerce / WooCommerce Subscriptions handle the native payment flow.
 * Version: 1.0.1
 * Author: FirstTracks Marketing
 * Author URI: https://firsttracksmarketing.com
 * Requires Plugins: woocommerce, woocommerce-subscriptions
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action( 'before_woocommerce_init', function () {
	if ( class_exists( '\\Automattic\\WooCommerce\\Utilities\\FeaturesUtil' ) ) {
		\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility(
			'custom_order_tables',
			__FILE__,
			true
		);
	}
} );

final class CEG_No_Login_Order_Payment_Links {

	const META_NONCE   = '_ceg_nlp_nonce';
	const META_EXPIRES = '_ceg_nlp_expires';
	const META_SHIPPING_SNAPSHOT = '_ceg_nlp_shipping_snapshot';
	const LINK_DAYS    = 30;
	const SESSION_AUTH                 = 'ceg_nlp_payment_auth';
	const SESSION_REGULAR              = 'ceg_nlp_regular_checkout_order';
	const SESSION_SUBSCRIPTION_ADDRESS = 'ceg_nlp_subscription_address_order';
	const SESSION_SUBSCRIPTION_SHIPPING = 'ceg_nlp_subscription_shipping_snapshot';

	public static function init() {
		if ( ! class_exists( 'WooCommerce' ) || ! class_exists( 'WC_Subscriptions' ) ) {
			return;
		}

		add_action( 'add_meta_boxes', array( __CLASS__, 'add_order_meta_box' ) );
		add_action( 'admin_post_ceg_generate_no_login_payment_link', array( __CLASS__, 'generate_link_action' ) );

		/*
		 * Authenticate before WooCommerce's native pay_action (wp priority 20).
		 * WooCommerce Subscriptions then sees a normal logged-in customer when its
		 * maybe_setup_cart() callback runs at template_redirect priority 100.
		 */
		add_action( 'wp', array( __CLASS__, 'authenticate_magic_link_customer' ), 1 );

		/* Keep payment permission scoped to this exact signed order. */
		add_filter( 'user_has_cap', array( __CLASS__, 'allow_magic_link_payment' ), 20, 4 );

		/* WooCommerce has a separate order email verification gate. */
		add_filter( 'woocommerce_order_email_verification_required', array( __CLASS__, 'skip_email_verification_for_magic_link' ), 20, 3 );

		/* Permit invoice-style On hold orders only while this signed authorization is active. */
		add_filter( 'woocommerce_valid_order_statuses_for_payment', array( __CLASS__, 'allow_on_hold_for_magic_link' ), 20, 2 );

		/*
		 * Regular WooCommerce orders do not have the cart-rebuild checkout flow that
		 * WooCommerce Subscriptions adds. These hooks let a signed regular order use
		 * the normal Checkout page while still reusing the existing order.
		 */
		add_action( 'woocommerce_before_calculate_totals', array( __CLASS__, 'apply_regular_order_prices' ), 99999 );
		add_action( 'woocommerce_cart_calculate_fees', array( __CLASS__, 'apply_regular_order_fees' ), 99999 );
		add_action( 'woocommerce_cart_loaded_from_session', array( __CLASS__, 'restore_regular_order_checkout_session' ), 20 );
		add_filter( 'woocommerce_create_order', array( __CLASS__, 'refresh_regular_order_cart_hash_for_classic_checkout' ), 5, 2 );
		add_filter( 'woocommerce_order_has_status', array( __CLASS__, 'support_regular_order_resume_status' ), 20, 3 );

		/*
		 * Checkout Blocks gets its initial address values from WC()->customer through
		 * the Store API. WCS only provides an order-address override for classic
		 * checkout, so preserve and expose the source order's shipping address here.
		 */
		add_action( 'woocommerce_cart_loaded_from_session', array( __CLASS__, 'restore_subscription_checkout_addresses' ), 99999 );

		/*
		 * WooCommerce removes a cart item from the session when product->is_purchasable()
		 * becomes false. Limited subscription products can hit that check while an
		 * existing initial/renewal payment order is being resumed in Checkout Blocks.
		 * Use the cart item's WCS payment metadata to preserve only the authorized
		 * existing-order payment item; normal subscription purchases remain untouched.
		 */
		add_filter( 'woocommerce_cart_item_is_purchasable', array( __CLASS__, 'allow_subscription_payment_cart_item' ), PHP_INT_MAX, 4 );

		/*
		 * WCS limited-subscription logic can cache a false product-level
		 * is_purchasable() result before Checkout Blocks restores all of the
		 * existing-order payment state. Force only the product that belongs to
		 * the authenticated existing subscription payment order back to
		 * purchasable. This runs after WCS_Limiter's priority-12 filters.
		 */
		add_filter( 'woocommerce_subscription_is_purchasable', array( __CLASS__, 'allow_authorized_subscription_product_payment' ), PHP_INT_MAX, 2 );
		add_filter( 'woocommerce_subscription_variation_is_purchasable', array( __CLASS__, 'allow_authorized_subscription_product_payment' ), PHP_INT_MAX, 2 );

		/*
		 * WooCommerce Store API currently promotes any pre-existing error notice
		 * in the WC session to woocommerce_rest_cart_item_error (409) and then
		 * restores it, which can make this particular cart-removal notice persist
		 * forever after an earlier failed attempt. Remove only that stale notice
		 * for our authenticated existing-subscription payment checkout.
		 */
		add_action( 'woocommerce_load_cart_from_session', array( __CLASS__, 'clear_stale_subscription_payment_cart_notice' ), PHP_INT_MAX );
		add_filter( 'rest_request_before_callbacks', array( __CLASS__, 'clear_stale_subscription_payment_cart_notice_before_store_api' ), 0, 3 );

		/*
		 * WCS empties/rebuilds the cart after our magic-link authentication callback.
		 * Reapply the order addresses AFTER WCS finishes that native rebuild so the
		 * authenticated customer-session snapshot used by Checkout Blocks contains
		 * the actual order shipping address.
		 */
		add_action( 'wcs_after_parent_order_setup_cart', array( __CLASS__, 'after_wcs_order_setup_cart' ), 99999, 2 );
		add_action( 'wcs_after_renewal_setup_cart_subscriptions', array( __CLASS__, 'after_wcs_order_setup_cart' ), 99999, 2 );

		foreach ( array( 'first_name', 'last_name', 'company', 'address_1', 'address_2', 'city', 'state', 'postcode', 'country', 'phone' ) as $shipping_field ) {
			add_filter( 'woocommerce_customer_get_shipping_' . $shipping_field, array( __CLASS__, 'filter_subscription_checkout_shipping_value' ), 99999, 2 );
		}
		add_action( 'woocommerce_store_api_cart_update_customer_from_request', array( __CLASS__, 'preserve_subscription_address_during_store_api_update' ), 99999, 2 );
		add_action( 'woocommerce_store_api_checkout_update_customer_from_request', array( __CLASS__, 'preserve_subscription_address_during_store_api_update' ), 99999, 2 );

		/*
		 * Checkout Blocks reuses pending subscription orders as Store API draft orders.
		 * Before the Store API callback runs, seed WC()->customer from a durable snapshot
		 * of the order's original shipping address. After the callback, also patch the
		 * initial GET response so the React cart store receives the same address.
		 */
		add_filter( 'rest_request_before_callbacks', array( __CLASS__, 'seed_subscription_shipping_before_store_api' ), 1, 3 );
		add_filter( 'rest_post_dispatch', array( __CLASS__, 'patch_subscription_shipping_in_store_api_response' ), 99999, 3 );
		add_action( 'woocommerce_store_api_checkout_update_order_meta', array( __CLASS__, 'restore_subscription_shipping_on_draft_order' ), 99999, 1 );

		/*
		 * Checkout Block maintains customer addresses in its client-side wc/store/cart
		 * data store. Hydrate that store from the source subscription order so the
		 * visible form gets the same address WCS supplies to classic checkout.
		 */
		add_action( 'wp_footer', array( __CLASS__, 'render_subscription_checkout_block_prefill' ), 100 );

		/* A paid order no longer needs a usable magic link. */
		add_action( 'woocommerce_payment_complete', array( __CLASS__, 'revoke_link_after_payment' ) );
	}

	public static function add_order_meta_box() {
		$screens = array( 'shop_order' );

		if ( function_exists( 'wc_get_page_screen_id' ) ) {
			$screens[] = wc_get_page_screen_id( 'shop-order' );
		}

		foreach ( array_unique( array_filter( $screens ) ) as $screen ) {
			add_meta_box(
				'ceg-no-login-payment-link',
				__( 'Magic Payment Link', 'ceg-no-login-order-payment' ),
				array( __CLASS__, 'render_order_meta_box' ),
				$screen,
				'side',
				'high'
			);
		}
	}

	private static function get_order_from_meta_box_object( $object ) {
		if ( $object instanceof WC_Order ) {
			return $object;
		}

		if ( $object instanceof WP_Post ) {
			return wc_get_order( $object->ID );
		}

		$order_id = 0;

		if ( isset( $_GET['id'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$order_id = absint( $_GET['id'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		} elseif ( isset( $_GET['post'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$order_id = absint( $_GET['post'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}

		return $order_id ? wc_get_order( $order_id ) : false;
	}

	public static function render_order_meta_box( $object ) {
		$order = self::get_order_from_meta_box_object( $object );

		if ( ! $order ) {
			echo '<p>' . esc_html__( 'Unable to load this order.', 'ceg-no-login-order-payment' ) . '</p>';
			return;
		}

		$order_id = $order->get_id();
		$expires  = absint( $order->get_meta( self::META_EXPIRES, true ) );
		$nonce    = (string) $order->get_meta( self::META_NONCE, true );
		$link     = '';

		if ( $nonce && $expires && $expires > time() ) {
			$link = self::build_payment_link( $order, $expires, $nonce );
		}

		$resolved = self::resolve_customer_user( $order );

		if ( $resolved && $resolved['user'] instanceof WP_User && self::is_privileged_user( $resolved['user'] ) ) {
			echo '<p style="margin-top:0;color:#b32d2e;"><strong>' . esc_html__( 'Safety block:', 'ceg-no-login-order-payment' ) . '</strong> ' . esc_html__( 'This account has administrator/store-management privileges, so the magic link will not auto-login it.', 'ceg-no-login-order-payment' ) . '</p>';
		}

		$generate_url = wp_nonce_url(
			add_query_arg(
				array(
					'action'   => 'ceg_generate_no_login_payment_link',
					'order_id' => $order_id,
				),
				admin_url( 'admin-post.php' )
			),
			'ceg_generate_no_login_payment_link_' . $order_id
		);

		$field_id  = 'ceg-no-login-payment-url-' . $order_id;
		$button_id = 'ceg-copy-payment-link-' . $order_id;

		echo '<input type="text" id="' . esc_attr( $field_id ) . '" value="' . esc_attr( $link ) . '" readonly style="width:100%; margin-bottom:8px;" onclick="this.select();" />';

		if ( $expires ) {
			$expiration_text = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $expires );
			echo '<p style="margin:0 0 8px;color:#646970;font-size:12px;">' . esc_html__( 'Expires:', 'ceg-no-login-order-payment' ) . ' ' . esc_html( $expiration_text ) . '</p>';
		}

		echo '<p style="display:flex; gap:6px; flex-wrap:wrap; margin:0;">';
		echo '<button type="button" class="button" id="' . esc_attr( $button_id ) . '"' . ( $link ? '' : ' disabled' ) . '>' . esc_html__( 'Copy link', 'ceg-no-login-order-payment' ) . '</button>';

		$confirm = $link
			? ' onclick="return confirm(\'' . esc_js( __( 'Generate a new link? The current link will stop working.', 'ceg-no-login-order-payment' ) ) . '\');"'
			: '';

		echo '<a class="button button-primary" href="' . esc_url( $generate_url ) . '"' . $confirm . '>' . esc_html__( 'Generate link', 'ceg-no-login-order-payment' ) . '</a>';
		echo '</p>';

		if ( $link ) {
			echo '<script>
		(function(){
			var button = document.getElementById(' . wp_json_encode( $button_id ) . ');
			var field = document.getElementById(' . wp_json_encode( $field_id ) . ');
			if (!button || !field) return;
			button.addEventListener("click", function(){
				var original = button.textContent;
				var done = function(){
					button.textContent = "Copied!";
					setTimeout(function(){ button.textContent = original; }, 1500);
				};
				if (navigator.clipboard && window.isSecureContext) {
					navigator.clipboard.writeText(field.value).then(done).catch(function(){
						field.focus(); field.select(); document.execCommand("copy"); done();
					});
				} else {
					field.focus(); field.select(); document.execCommand("copy"); done();
				}
			});
		})();
		</script>';
		}
	}

	private static function customer_source_label( $source ) {
		switch ( $source ) {
			case 'order':
				return __( 'Customer account comes from the WooCommerce order.', 'ceg-no-login-order-payment' );
			case 'subscription':
				return __( 'Customer account comes from the related WooCommerce Subscription.', 'ceg-no-login-order-payment' );
			case 'billing_email':
				return __( 'Order had no customer ID; matched an existing WordPress user by billing email.', 'ceg-no-login-order-payment' );
			default:
				return '';
		}
	}

	public static function generate_link_action() {
		$order_id = isset( $_GET['order_id'] ) ? absint( $_GET['order_id'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( ! $order_id ) {
			wp_die( esc_html__( 'Invalid order.', 'ceg-no-login-order-payment' ) );
		}

		check_admin_referer( 'ceg_generate_no_login_payment_link_' . $order_id );

		if ( ! current_user_can( 'manage_woocommerce' ) && ! current_user_can( 'edit_shop_orders' ) ) {
			wp_die( esc_html__( 'You do not have permission to generate payment links.', 'ceg-no-login-order-payment' ) );
		}

		$order = wc_get_order( $order_id );
		if ( ! $order ) {
			wp_die( esc_html__( 'Order not found.', 'ceg-no-login-order-payment' ) );
		}

		$expires = time() + ( self::LINK_DAYS * DAY_IN_SECONDS );
		$nonce   = self::create_random_nonce();

		$order->update_meta_data( self::META_NONCE, $nonce );
		$order->update_meta_data( self::META_EXPIRES, $expires );

		/* Keep an immutable copy of the shipping address used when this link was generated. */
		if ( self::is_subscription_related_order( $order ) ) {
			$snapshot = self::build_subscription_shipping_snapshot( $order, false );
			if ( self::shipping_snapshot_has_location( $snapshot ) ) {
				$order->update_meta_data( self::META_SHIPPING_SNAPSHOT, $snapshot );
			}
		}

		$order->save();

		$redirect = wp_get_referer();
		if ( ! $redirect ) {
			$redirect = admin_url( 'post.php?post=' . $order_id . '&action=edit' );
		}

		wp_safe_redirect( add_query_arg( 'ceg_payment_link_generated', '1', $redirect ) );
		exit;
	}

	private static function create_random_nonce() {
		try {
			return bin2hex( random_bytes( 32 ) );
		} catch ( Exception $e ) {
			return wp_generate_password( 64, false, false );
		}
	}

	private static function build_payment_link( $order, $expires, $nonce ) {
		$signature = self::make_signature( $order, $expires, $nonce );

		return add_query_arg(
			array(
				'ceg_nlp'         => '1',
				'ceg_nlp_expires' => $expires,
				'ceg_nlp_sig'     => $signature,
			),
			$order->get_checkout_payment_url()
		);
	}

	private static function make_signature( $order, $expires, $nonce ) {
		$data = implode(
			'|',
			array(
				$order->get_id(),
				absint( $expires ),
				$nonce,
				$order->get_order_key(),
			)
		);

		return hash_hmac( 'sha256', $data, wp_salt( 'auth' ) );
	}

	private static function request_has_valid_magic_link( $order_id ) {
		if ( empty( $_GET['ceg_nlp'] ) || '1' !== (string) wp_unslash( $_GET['ceg_nlp'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return false;
		}

		$expires = isset( $_GET['ceg_nlp_expires'] ) ? absint( $_GET['ceg_nlp_expires'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$sig     = isset( $_GET['ceg_nlp_sig'] ) ? sanitize_text_field( wp_unslash( $_GET['ceg_nlp_sig'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$key     = isset( $_GET['key'] ) ? wc_clean( wp_unslash( $_GET['key'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		return self::validate_magic_authorization( $order_id, $expires, $sig, $key );
	}

	private static function validate_magic_authorization( $order_id, $expires, $sig, $key ) {
		$order_id = absint( $order_id );
		$expires  = absint( $expires );
		$sig      = (string) $sig;
		$key      = (string) $key;

		if ( ! $order_id || ! $expires || ! $sig || ! $key || $expires < time() ) {
			return false;
		}

		$order = wc_get_order( $order_id );
		if ( ! $order || ! hash_equals( (string) $order->get_order_key(), $key ) ) {
			return false;
		}

		$stored_expires = absint( $order->get_meta( self::META_EXPIRES, true ) );
		$stored_nonce   = (string) $order->get_meta( self::META_NONCE, true );

		if ( ! $stored_nonce || ! $stored_expires || $stored_expires !== $expires ) {
			return false;
		}

		$expected = self::make_signature( $order, $expires, $stored_nonce );
		return hash_equals( $expected, $sig );
	}

	private static function store_magic_session_authorization( $order ) {
		if ( ! $order instanceof WC_Order || ! function_exists( 'WC' ) || ! WC()->session ) {
			return false;
		}

		$order_id = $order->get_id();
		$expires  = isset( $_GET['ceg_nlp_expires'] ) ? absint( $_GET['ceg_nlp_expires'] ) : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$sig      = isset( $_GET['ceg_nlp_sig'] ) ? sanitize_text_field( wp_unslash( $_GET['ceg_nlp_sig'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$key      = isset( $_GET['key'] ) ? wc_clean( wp_unslash( $_GET['key'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( ! self::validate_magic_authorization( $order_id, $expires, $sig, $key ) ) {
			return false;
		}

		WC()->session->set(
			self::SESSION_AUTH,
			array(
				'order_id' => $order_id,
				'expires'  => $expires,
				'sig'      => $sig,
				'key'      => $key,
			)
		);

		if ( is_callable( array( WC()->session, 'set_customer_session_cookie' ) ) ) {
			WC()->session->set_customer_session_cookie( true );
		}

		return true;
	}

	private static function session_has_valid_magic_link( $order_id = 0 ) {
		if ( ! function_exists( 'WC' ) || ! WC()->session ) {
			return false;
		}

		$auth = WC()->session->get( self::SESSION_AUTH, array() );
		if ( ! is_array( $auth ) || empty( $auth['order_id'] ) ) {
			return false;
		}

		$session_order_id = absint( $auth['order_id'] );
		if ( $order_id && absint( $order_id ) !== $session_order_id ) {
			return false;
		}

		return self::validate_magic_authorization(
			$session_order_id,
			isset( $auth['expires'] ) ? absint( $auth['expires'] ) : 0,
			isset( $auth['sig'] ) ? (string) $auth['sig'] : '',
			isset( $auth['key'] ) ? (string) $auth['key'] : ''
		);
	}

	private static function has_valid_magic_authorization( $order_id ) {
		return self::request_has_valid_magic_link( $order_id ) || self::session_has_valid_magic_link( $order_id );
	}

	/**
	 * Resolve the account to sign in.
	 * Priority: order customer -> related subscription customer -> billing email.
	 */
	private static function resolve_customer_user( $order ) {
		if ( ! $order instanceof WC_Order ) {
			return false;
		}

		$customer_id = absint( $order->get_customer_id() );
		if ( $customer_id ) {
			$user = get_user_by( 'id', $customer_id );
			if ( $user instanceof WP_User ) {
				return array( 'user' => $user, 'source' => 'order' );
			}
		}

		$subscription_ids = array();

		if ( function_exists( 'wcs_order_contains_subscription' ) && function_exists( 'wcs_get_subscriptions_for_order' ) ) {
			if ( wcs_order_contains_subscription( $order, 'parent' ) || wcs_order_contains_subscription( $order, 'resubscribe' ) ) {
				$subscriptions = wcs_get_subscriptions_for_order( $order );
				foreach ( $subscriptions as $subscription ) {
					if ( $subscription instanceof WC_Subscription ) {
						$subscription_ids[] = absint( $subscription->get_customer_id() );
					}
				}
			}
		}

		if ( function_exists( 'wcs_order_contains_renewal' ) && function_exists( 'wcs_get_subscriptions_for_renewal_order' ) && wcs_order_contains_renewal( $order ) ) {
			$subscriptions = wcs_get_subscriptions_for_renewal_order( $order );
			foreach ( $subscriptions as $subscription ) {
				if ( $subscription instanceof WC_Subscription ) {
					$subscription_ids[] = absint( $subscription->get_customer_id() );
				}
			}
		}

		foreach ( array_unique( array_filter( $subscription_ids ) ) as $subscription_customer_id ) {
			$user = get_user_by( 'id', $subscription_customer_id );
			if ( $user instanceof WP_User ) {
				return array( 'user' => $user, 'source' => 'subscription' );
			}
		}

		$billing_email = sanitize_email( $order->get_billing_email() );
		if ( $billing_email ) {
			$user = get_user_by( 'email', $billing_email );
			if ( $user instanceof WP_User ) {
				return array( 'user' => $user, 'source' => 'billing_email' );
			}
		}

		return false;
	}

	private static function is_privileged_user( $user ) {
		return $user instanceof WP_User && (
			user_can( $user, 'manage_options' ) ||
			user_can( $user, 'manage_woocommerce' ) ||
			user_can( $user, 'edit_shop_orders' )
		);
	}

	private static function establish_customer_login( $user ) {
		if ( ! $user instanceof WP_User || ! $user->ID ) {
			return false;
		}

		if ( headers_sent() ) {
			return false;
		}

		$customer_id = absint( $user->ID );

		if ( function_exists( 'wc_set_customer_auth_cookie' ) ) {
			wc_set_customer_auth_cookie( $customer_id );
		} else {
			wp_set_current_user( $customer_id, $user->user_login );
			wp_set_auth_cookie( $customer_id, true, is_ssl() );
		}

		/* Keep this request aligned with the cookie that was just issued. */
		wp_set_current_user( $customer_id, $user->user_login );

		if ( function_exists( 'WC' ) ) {
			if ( WC()->session && is_callable( array( WC()->session, 'init_session_cookie' ) ) ) {
				WC()->session->init_session_cookie();
			}

			if ( class_exists( 'WC_Customer' ) ) {
				WC()->customer = new WC_Customer( $customer_id, true );
			}

			if ( WC()->session && is_callable( array( WC()->session, 'set_customer_session_cookie' ) ) ) {
				WC()->session->set_customer_session_cookie( true );
			}
		}

		/* wp_signon(), used by the normal WooCommerce login form, fires this action. */
		do_action( 'wp_login', $user->user_login, $user );

		return is_user_logged_in() && get_current_user_id() === $customer_id;
	}

	/**
	 * Sign in the customer while still on the native order-pay request.
	 * Subscription carts are rebuilt natively by WooCommerce Subscriptions.
	 * When a new login is created, use one intermediate redirect so the browser
	 * returns the fresh auth/session cookies before WCS performs that rebuild.
	 */
	public static function authenticate_magic_link_customer() {
		global $wp;

		if (
			empty( $wp->query_vars['order-pay'] ) ||
			empty( $_GET['pay_for_order'] ) || // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			empty( $_GET['key'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		) {
			return;
		}

		$order_id = absint( $wp->query_vars['order-pay'] );
		$order    = $order_id ? wc_get_order( $order_id ) : false;

		if ( ! $order instanceof WC_Order || ! self::request_has_valid_magic_link( $order_id ) ) {
			return;
		}

		$resolved = self::resolve_customer_user( $order );
		if ( ! $resolved || ! ( $resolved['user'] instanceof WP_User ) ) {
			wp_die(
				esc_html__( 'This order does not have a customer account that can be signed in. Assign the order/subscription to a WordPress customer or make sure the billing email matches an existing user.', 'ceg-no-login-order-payment' ),
				esc_html__( 'Customer Account Not Found', 'ceg-no-login-order-payment' ),
				array( 'response' => 400 )
			);
		}

		$customer_user = $resolved['user'];

		if ( self::is_privileged_user( $customer_user ) ) {
			wp_die(
				esc_html__( 'For security, magic payment links cannot passwordlessly sign in administrator or store-management accounts. Use a normal customer account for testing.', 'ceg-no-login-order-payment' ),
				esc_html__( 'Payment Link Sign-In Blocked', 'ceg-no-login-order-payment' ),
				array( 'response' => 403 )
			);
		}

		$current_user = wp_get_current_user();
		$did_login    = false;

		if (
			$current_user instanceof WP_User &&
			$current_user->exists() &&
			$current_user->ID !== $customer_user->ID &&
			self::is_privileged_user( $current_user )
		) {
			wp_die(
				esc_html__( 'This browser is currently logged in as an administrator or store staff member. Open the payment link in a private/incognito window so it can sign in the customer.', 'ceg-no-login-order-payment' ),
				esc_html__( 'Use a Private Window', 'ceg-no-login-order-payment' ),
				array( 'response' => 409 )
			);
		}

		if ( get_current_user_id() !== absint( $customer_user->ID ) ) {
			if ( $current_user instanceof WP_User && $current_user->exists() ) {
				wp_logout();
			}

			if ( ! self::establish_customer_login( $customer_user ) ) {
				wp_die(
					esc_html__( 'WordPress could not establish the customer login cookie. Check that no plugin or proxy is preventing authentication cookies from being set.', 'ceg-no-login-order-payment' ),
					esc_html__( 'Unable to Sign In', 'ceg-no-login-order-payment' ),
					array( 'response' => 500 )
				);
			}

			$did_login = true;
		}

		/*
		 * Persist the signed permission into the authenticated WC session. This is
		 * useful when the order itself has customer_id 0 but the related subscription
		 * (or billing email) identifies the real customer. WCS validates pay_for_order
		 * again when loading the subscription cart on Checkout.
		 */
		if ( ! self::store_magic_session_authorization( $order ) ) {
			wp_die(
				esc_html__( 'The signed payment authorization could not be stored in the WooCommerce customer session.', 'ceg-no-login-order-payment' ),
				esc_html__( 'Unable to Prepare Payment Session', 'ceg-no-login-order-payment' ),
				array( 'response' => 500 )
			);
		}

		/*
		 * When the magic link has just created the WordPress/WooCommerce login, give
		 * the browser one clean request to send those new cookies back before WCS
		 * empties and rebuilds the subscription cart. Without this hop, some Checkout
		 * Block setups reach /checkout/ before the newly authenticated WC session is
		 * fully available and show an empty cart. A manual second visit works for the
		 * same reason: the cookies already exist by then.
		 */
		if (
			$did_login &&
			self::is_subscription_related_order( $order ) &&
			empty( $_GET['ceg_nlp_session_ready'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		) {
			if ( WC()->session && is_callable( array( WC()->session, 'save_data' ) ) ) {
				WC()->session->save_data();
			}

			$redirect = add_query_arg(
				array(
					'ceg_nlp'               => '1',
					'ceg_nlp_expires'       => isset( $_GET['ceg_nlp_expires'] ) ? absint( $_GET['ceg_nlp_expires'] ) : 0, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					'ceg_nlp_sig'           => isset( $_GET['ceg_nlp_sig'] ) ? sanitize_text_field( wp_unslash( $_GET['ceg_nlp_sig'] ) ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					'ceg_nlp_session_ready' => '1',
				),
				$order->get_checkout_payment_url()
			);

			wp_safe_redirect( $redirect );
			exit;
		}

		/*
		 * WooCommerce Subscriptions already has its own native cart rebuild flow, so
		 * leave subscription-related orders alone and let WCS redirect to Checkout.
		 * Core WooCommerce does not do that for regular orders, so build the regular
		 * order into the cart here and redirect it to the normal Checkout page.
		 */
		if ( self::is_subscription_related_order( $order ) ) {
			/*
			 * WCS rebuilds only the subscription cart. Checkout Blocks then treats the
			 * existing pending order as a Store API draft and syncs it from WC()->customer.
			 * Snapshot the original shipping address before that sync can touch the order.
			 */
			WC()->session->set( self::SESSION_SUBSCRIPTION_ADDRESS, $order->get_id() );
			$snapshot = self::ensure_subscription_shipping_snapshot( $order );
			if ( self::shipping_snapshot_has_location( $snapshot ) ) {
				WC()->session->set( self::SESSION_SUBSCRIPTION_SHIPPING, array(
					'order_id' => $order->get_id(),
					'shipping' => $snapshot,
				) );
			}
			self::copy_order_addresses_to_customer( $order );
		} else {
			WC()->session->set( self::SESSION_SUBSCRIPTION_ADDRESS, null );
			self::setup_regular_order_checkout( $order );
		}
	}

	private static function is_subscription_related_order( $order ) {
		if ( ! $order instanceof WC_Order ) {
			return false;
		}

		if ( function_exists( 'wcs_order_contains_renewal' ) && wcs_order_contains_renewal( $order ) ) {
			return true;
		}

		if ( function_exists( 'wcs_order_contains_subscription' ) ) {
			foreach ( array( 'parent', 'resubscribe' ) as $type ) {
				if ( wcs_order_contains_subscription( $order, $type ) ) {
					return true;
				}
			}
		}

		if ( function_exists( 'wcs_order_contains_switch' ) && wcs_order_contains_switch( $order ) ) {
			return true;
		}

		return false;
	}

	private static function ensure_wc_cart() {
		if ( ! function_exists( 'WC' ) ) {
			return false;
		}

		if ( null === WC()->session && is_callable( array( WC(), 'initialize_session' ) ) ) {
			WC()->initialize_session();
		}

		if ( null === WC()->cart && function_exists( 'wc_load_cart' ) ) {
			wc_load_cart();
		}

		return WC()->session && WC()->cart;
	}

	/**
	 * Return the order shipping address in the shape WooCommerce customer/session
	 * setters expect. If an imported/admin-created order has street data but is
	 * missing country/state selectors, borrow only those selectors from billing so
	 * Checkout Blocks can hydrate the address form.
	 *
	 * @param WC_Order $order Order object.
	 * @return array
	 */
	private static function shipping_snapshot_has_location( $shipping ) {
		if ( ! is_array( $shipping ) ) {
			return false;
		}

		foreach ( array( 'address_1', 'city', 'postcode' ) as $field ) {
			if ( ! empty( $shipping[ $field ] ) ) {
				return true;
			}
		}

		return false;
	}

	private static function normalize_shipping_snapshot( $shipping, $billing = array() ) {
		$shipping = is_array( $shipping ) ? $shipping : array();
		$billing  = is_array( $billing ) ? $billing : array();
		$clean    = array();

		foreach ( array( 'first_name', 'last_name', 'company', 'address_1', 'address_2', 'city', 'state', 'postcode', 'country', 'phone' ) as $field ) {
			$clean[ $field ] = isset( $shipping[ $field ] ) ? (string) $shipping[ $field ] : '';
		}

		/* Imported/admin-created orders sometimes omit only the shipping country/state. */
		if ( self::shipping_snapshot_has_location( $clean ) ) {
			if ( '' === $clean['country'] && ! empty( $billing['country'] ) ) {
				$clean['country'] = (string) $billing['country'];
			}
			if ( '' === $clean['state'] && ! empty( $billing['state'] ) && $clean['country'] === (string) ( $billing['country'] ?? '' ) ) {
				$clean['state'] = (string) $billing['state'];
			}
		}

		return $clean;
	}

	/**
	 * Build a shipping snapshot from the order, with a related subscription as a
	 * fallback only when the order itself no longer contains a usable location.
	 */
	private static function build_subscription_shipping_snapshot( $order, $allow_related_subscription = true ) {
		if ( ! $order instanceof WC_Order ) {
			return array();
		}

		$billing  = $order->get_address( 'billing' );
		$shipping = self::normalize_shipping_snapshot( $order->get_address( 'shipping' ), $billing );
		if ( self::shipping_snapshot_has_location( $shipping ) || ! $allow_related_subscription ) {
			return $shipping;
		}

		$subscriptions = array();
		if ( function_exists( 'wcs_order_contains_renewal' ) && function_exists( 'wcs_get_subscriptions_for_renewal_order' ) && wcs_order_contains_renewal( $order ) ) {
			$subscriptions = wcs_get_subscriptions_for_renewal_order( $order );
		} elseif ( function_exists( 'wcs_get_subscriptions_for_order' ) ) {
			$subscriptions = wcs_get_subscriptions_for_order( $order );
		}

		foreach ( $subscriptions as $subscription ) {
			if ( ! $subscription instanceof WC_Subscription ) {
				continue;
			}
			$candidate = self::normalize_shipping_snapshot( $subscription->get_address( 'shipping' ), $subscription->get_address( 'billing' ) );
			if ( self::shipping_snapshot_has_location( $candidate ) ) {
				return $candidate;
			}
		}

		return $shipping;
	}

	private static function ensure_subscription_shipping_snapshot( $order ) {
		if ( ! $order instanceof WC_Order ) {
			return array();
		}

		$stored = $order->get_meta( self::META_SHIPPING_SNAPSHOT, true );
		if ( is_array( $stored ) && self::shipping_snapshot_has_location( $stored ) ) {
			return self::normalize_shipping_snapshot( $stored, $order->get_address( 'billing' ) );
		}

		$snapshot = self::build_subscription_shipping_snapshot( $order, true );
		if ( self::shipping_snapshot_has_location( $snapshot ) ) {
			$order->update_meta_data( self::META_SHIPPING_SNAPSHOT, $snapshot );
			$order->save_meta_data();
		}
		return $snapshot;
	}

	private static function get_session_subscription_shipping_snapshot( $order_id ) {
		if ( ! function_exists( 'WC' ) || ! WC()->session ) {
			return array();
		}
		$data = WC()->session->get( self::SESSION_SUBSCRIPTION_SHIPPING, array() );
		if ( ! is_array( $data ) || absint( $data['order_id'] ?? 0 ) !== absint( $order_id ) || ! is_array( $data['shipping'] ?? null ) ) {
			return array();
		}
		return self::normalize_shipping_snapshot( $data['shipping'] );
	}

	private static function get_order_shipping_prefill( $order ) {
		if ( ! $order instanceof WC_Order ) {
			return array();
		}

		if ( self::is_subscription_related_order( $order ) ) {
			$session_snapshot = self::get_session_subscription_shipping_snapshot( $order->get_id() );
			if ( self::shipping_snapshot_has_location( $session_snapshot ) ) {
				return $session_snapshot;
			}

			$stored = $order->get_meta( self::META_SHIPPING_SNAPSHOT, true );
			if ( is_array( $stored ) && self::shipping_snapshot_has_location( $stored ) ) {
				return self::normalize_shipping_snapshot( $stored, $order->get_address( 'billing' ) );
			}
		}

		return self::normalize_shipping_snapshot( $order->get_address( 'shipping' ), $order->get_address( 'billing' ) );
	}

	private static function copy_order_addresses_to_customer( $order ) {
		if ( ! $order instanceof WC_Order || ! function_exists( 'WC' ) || ! WC()->customer ) {
			return;
		}

		$billing  = $order->get_address( 'billing' );
		$shipping = self::get_order_shipping_prefill( $order );

		foreach ( $billing as $key => $value ) {
			$setter = 'set_billing_' . $key;
			if ( is_callable( array( WC()->customer, $setter ) ) ) {
				WC()->customer->{$setter}( $value );
			}
		}

		foreach ( $shipping as $key => $value ) {
			$setter = 'set_shipping_' . $key;
			if ( is_callable( array( WC()->customer, $setter ) ) ) {
				WC()->customer->{$setter}( $value );
			}
		}

		if ( is_callable( array( WC()->customer, 'save' ) ) ) {
			WC()->customer->save();
		}
	}


	/**
	 * Return true while WooCommerce is serving a Store API request used by
	 * Cart/Checkout Blocks. The route can be present in either the pretty URL
	 * or the rest_route query parameter depending on permalink configuration.
	 */
	private static function is_store_api_request() {
		if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST ) {
			return false;
		}

		$route = '';

		if ( isset( $GLOBALS['wp']->query_vars['rest_route'] ) ) {
			$route = (string) $GLOBALS['wp']->query_vars['rest_route'];
		} elseif ( isset( $_GET['rest_route'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$route = (string) wp_unslash( $_GET['rest_route'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] )
			? (string) wp_unslash( $_SERVER['REQUEST_URI'] )
			: '';

		return false !== strpos( $route, '/wc/store/' ) || false !== strpos( $request_uri, '/wc/store/' );
	}


	/**
	 * Return the existing subscription payment order ID encoded in WCS cart item
	 * data. WCS uses these cart flags for its own payment-session validation and
	 * can restore order_awaiting_payment/store_api_draft_order from them.
	 *
	 * @return int
	 */
	private static function get_subscription_payment_order_id_from_cart() {
		if ( ! function_exists( 'WC' ) || ! WC()->cart ) {
			return 0;
		}

		foreach ( WC()->cart->get_cart() as $cart_item ) {
			if ( ! is_array( $cart_item ) ) {
				continue;
			}

			if ( isset( $cart_item['subscription_initial_payment'] ) && is_array( $cart_item['subscription_initial_payment'] ) ) {
				$order_id = absint( $cart_item['subscription_initial_payment']['order_id'] ?? 0 );
				if ( $order_id ) {
					return $order_id;
				}
			}

			if ( isset( $cart_item['subscription_renewal'] ) && is_array( $cart_item['subscription_renewal'] ) ) {
				$order_id = absint( $cart_item['subscription_renewal']['renewal_order_id'] ?? 0 );
				if ( $order_id ) {
					return $order_id;
				}
			}
		}

		return 0;
	}

	/**
	 * Verify that the currently logged-in WordPress customer owns the WCS payment
	 * order. Once WCS has rebuilt the cart, this ownership check is the correct
	 * authorization boundary; the plugin's one-time magic-link session marker is
	 * no longer required for subsequent /checkout/ and Store API requests.
	 *
	 * @param WC_Order         $order    Payment order.
	 * @param WC_Customer|null $customer Current WooCommerce customer.
	 * @return bool
	 */
	private static function current_customer_owns_subscription_payment_order( $order, $customer = null ) {
		if ( ! $order instanceof WC_Order || ! self::is_subscription_related_order( $order ) || ! is_user_logged_in() ) {
			return false;
		}

		$current_user_id = absint( get_current_user_id() );
		if ( ! $current_user_id ) {
			return false;
		}

		/* A zero WC_Customer ID can occur while Blocks is bootstrapping; only reject a real mismatch. */
		if ( $customer instanceof WC_Customer ) {
			$wc_customer_id = absint( $customer->get_id() );
			if ( $wc_customer_id && $wc_customer_id !== $current_user_id ) {
				return false;
			}
		}

		$resolved = self::resolve_customer_user( $order );
		if ( ! $resolved || ! ( $resolved['user'] instanceof WP_User ) ) {
			return false;
		}

		return absint( $resolved['user']->ID ) === $current_user_id;
	}

	/**
	 * Get the subscription-related order whose shipping address should prefill
	 * Checkout. Prefer WCS's own native payment-session state. WCS explicitly
	 * treats order_awaiting_payment/store_api_draft_order and its cart-item flags
	 * as the resumable payment session and independently validates ownership.
	 *
	 * @param WC_Customer|null $customer Current WooCommerce customer.
	 * @return WC_Order|false
	 */
	private static function get_subscription_address_order( $customer = null ) {
		if ( ! function_exists( 'WC' ) || ! WC()->session || ! is_user_logged_in() ) {
			return false;
		}

		$order_id = absint( WC()->session->get( 'order_awaiting_payment', 0 ) );
		if ( ! $order_id ) {
			$order_id = absint( WC()->session->get( 'store_api_draft_order', 0 ) );
		}
		if ( ! $order_id ) {
			$order_id = self::get_subscription_payment_order_id_from_cart();
		}
		if ( ! $order_id ) {
			$order_id = absint( WC()->session->get( self::SESSION_SUBSCRIPTION_ADDRESS, 0 ) );
		}

		if ( ! $order_id ) {
			return false;
		}

		$order = wc_get_order( $order_id );
		if ( ! $order instanceof WC_Order || ! self::current_customer_owns_subscription_payment_order( $order, $customer ) ) {
			return false;
		}

		return $order;
	}

	/**
	 * Return the active existing subscription payment order for this customer.
	 *
	 * This intentionally checks several pieces of state because WCS and Checkout
	 * Blocks restore them at different moments in the request lifecycle. The
	 * authorization boundary is always the logged-in customer owning the order.
	 *
	 * @return WC_Order|false
	 */
	private static function get_authorized_subscription_payment_order() {
		if ( ! function_exists( 'WC' ) || ! WC()->session || ! is_user_logged_in() ) {
			return false;
		}

		$order_ids = array(
			absint( WC()->session->get( 'order_awaiting_payment', 0 ) ),
			absint( WC()->session->get( 'store_api_draft_order', 0 ) ),
			absint( WC()->session->get( self::SESSION_SUBSCRIPTION_ADDRESS, 0 ) ),
		);

		$auth = WC()->session->get( self::SESSION_AUTH, array() );
		if ( is_array( $auth ) && ! empty( $auth['order_id'] ) ) {
			$order_ids[] = absint( $auth['order_id'] );
		}

		$shipping_snapshot = WC()->session->get( self::SESSION_SUBSCRIPTION_SHIPPING, array() );
		if ( is_array( $shipping_snapshot ) && ! empty( $shipping_snapshot['order_id'] ) ) {
			$order_ids[] = absint( $shipping_snapshot['order_id'] );
		}

		/* WCS may still be in the process of restoring order_awaiting_payment. */
		$raw_cart = WC()->session->get( 'cart', array() );
		if ( is_array( $raw_cart ) ) {
			foreach ( $raw_cart as $cart_item ) {
				if ( ! is_array( $cart_item ) ) {
					continue;
				}
				if ( isset( $cart_item['subscription_initial_payment']['order_id'] ) ) {
					$order_ids[] = absint( $cart_item['subscription_initial_payment']['order_id'] );
				}
				if ( isset( $cart_item['subscription_renewal']['renewal_order_id'] ) ) {
					$order_ids[] = absint( $cart_item['subscription_renewal']['renewal_order_id'] );
				}
			}
		}

		foreach ( array_unique( array_filter( $order_ids ) ) as $order_id ) {
			$order = wc_get_order( $order_id );
			if ( ! $order instanceof WC_Order ) {
				continue;
			}
			if ( $order->is_paid() || $order->has_status( array( 'cancelled', 'refunded', 'trash' ) ) ) {
				continue;
			}
			if ( ! self::current_customer_owns_subscription_payment_order( $order, WC()->customer ) ) {
				continue;
			}
			return $order;
		}

		return false;
	}

	/**
	 * Check whether a product is one of the line items on an order.
	 *
	 * @param WC_Order   $order   Order being paid.
	 * @param WC_Product $product Product being validated.
	 * @return bool
	 */
	private static function order_contains_product( $order, $product ) {
		if ( ! $order instanceof WC_Order || ! $product instanceof WC_Product ) {
			return false;
		}

		$product_id = absint( $product->get_id() );
		$parent_id  = absint( $product->get_parent_id() );

		foreach ( $order->get_items( 'line_item' ) as $item ) {
			if ( ! $item instanceof WC_Order_Item_Product ) {
				continue;
			}
			$item_product_id   = absint( $item->get_product_id() );
			$item_variation_id = absint( $item->get_variation_id() );

			if (
				$product_id === $item_product_id ||
				$product_id === $item_variation_id ||
				( $parent_id && $parent_id === $item_product_id )
			) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Final product-level purchasability override for a signed existing-order
	 * subscription payment. WCS_Limiter caches its own false result, so this must
	 * run at PHP_INT_MAX on the subscription product filters.
	 */
	public static function allow_authorized_subscription_product_payment( $purchasable, $product ) {
		if ( true === $purchasable || ! $product instanceof WC_Product ) {
			return $purchasable;
		}

		$order = self::get_authorized_subscription_payment_order();
		if ( ! $order ) {
			return $purchasable;
		}

		return self::order_contains_product( $order, $product ) ? true : $purchasable;
	}

	/**
	 * Remove only the stale "can no longer be purchased" WC error notice while
	 * an authenticated existing subscription order is being paid. WooCommerce's
	 * Store API currently converts pre-existing notices into persistent 409 cart
	 * errors, so leaving this old notice in the session can block every retry.
	 */
	public static function clear_stale_subscription_payment_cart_notice() {
		$order = self::get_authorized_subscription_payment_order();
		if ( ! $order || ! function_exists( 'WC' ) || ! WC()->session ) {
			return;
		}

		$notices = WC()->session->get( 'wc_notices', array() );
		if ( ! is_array( $notices ) || empty( $notices['error'] ) || ! is_array( $notices['error'] ) ) {
			return;
		}

		$changed = false;
		foreach ( $notices['error'] as $index => $notice ) {
			$message = is_array( $notice ) ? (string) ( $notice['notice'] ?? '' ) : (string) $notice;
			$plain   = html_entity_decode( wp_strip_all_tags( $message ), ENT_QUOTES, get_bloginfo( 'charset' ) ?: 'UTF-8' );

			if ( false !== stripos( $plain, 'has been removed from your cart because it can no longer be purchased' ) ) {
				unset( $notices['error'][ $index ] );
				$changed = true;
			}
		}

		if ( $changed ) {
			$notices['error'] = array_values( $notices['error'] );
			if ( empty( $notices['error'] ) ) {
				unset( $notices['error'] );
			}
			WC()->session->set( 'wc_notices', $notices );
		}
	}

	/**
	 * Same stale-notice cleanup immediately before Store API callbacks. This is
	 * needed for retries because current WooCommerce restores the pre-request
	 * notice snapshot after validating the cart.
	 */
	public static function clear_stale_subscription_payment_cart_notice_before_store_api( $response, $handler, $request ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( $request instanceof WP_REST_Request && 0 === strpos( (string) $request->get_route(), '/wc/store/' ) ) {
			self::clear_stale_subscription_payment_cart_notice();
		}
		return $response;
	}

	/**
	 * Keep a WooCommerce Subscriptions existing-order payment item purchasable
	 * when the underlying product is limited for the customer.
	 *
	 * WooCommerce validates product->is_purchasable() again while restoring the
	 * cart from session. WCS normally compensates for limited products via its
	 * order_awaiting_payment lookup, but Checkout Blocks can perform that check
	 * during a request where the product is already considered limited. The
	 * woocommerce_cart_item_is_purchasable hook exists specifically so cart-item
	 * context can override that product-level result.
	 *
	 * This override is intentionally narrow: the cart item must contain WCS's
	 * initial-payment or renewal metadata, it must point at the same native WCS
	 * payment session, and the logged-in customer must own the linked order.
	 *
	 * @param bool       $is_purchasable Product-level purchasability result.
	 * @param string     $cart_item_key  Cart item key.
	 * @param array      $values         Cart item session data.
	 * @param WC_Product $product        Product object.
	 * @return bool
	 */
	public static function allow_subscription_payment_cart_item( $is_purchasable, $cart_item_key, $values, $product ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( $is_purchasable || ! is_array( $values ) || ! $product instanceof WC_Product || ! is_user_logged_in() ) {
			return $is_purchasable;
		}

		$order_id = 0;

		if ( isset( $values['subscription_initial_payment'] ) && is_array( $values['subscription_initial_payment'] ) ) {
			$order_id = absint( $values['subscription_initial_payment']['order_id'] ?? 0 );
		} elseif ( isset( $values['subscription_renewal'] ) && is_array( $values['subscription_renewal'] ) ) {
			$order_id = absint( $values['subscription_renewal']['renewal_order_id'] ?? 0 );
		}

		if ( ! $order_id || ! function_exists( 'WC' ) || ! WC()->session ) {
			return $is_purchasable;
		}

		/* Require the same order to be the active WCS/Checkout payment session. */
		$session_order_ids = array_filter(
			array(
				absint( WC()->session->get( 'order_awaiting_payment', 0 ) ),
				absint( WC()->session->get( 'store_api_draft_order', 0 ) ),
				absint( WC()->session->get( self::SESSION_SUBSCRIPTION_ADDRESS, 0 ) ),
			)
		);

		if ( ! in_array( $order_id, $session_order_ids, true ) && ! self::session_has_valid_magic_link( $order_id ) ) {
			return $is_purchasable;
		}

		$order = wc_get_order( $order_id );
		if ( ! $order instanceof WC_Order || ! self::current_customer_owns_subscription_payment_order( $order, WC()->customer ) ) {
			return $is_purchasable;
		}

		/* Never revive an already-paid or terminal order. */
		if ( $order->is_paid() || $order->has_status( array( 'cancelled', 'refunded', 'trash' ) ) ) {
			return $is_purchasable;
		}

		/* Ensure this cart product actually exists on the linked payment order. */
		$product_id = absint( $product->get_id() );
		$parent_id  = absint( $product->get_parent_id() );
		$matches    = false;

		foreach ( $order->get_items( 'line_item' ) as $item ) {
			if ( ! $item instanceof WC_Order_Item_Product ) {
				continue;
			}

			$item_product_id   = absint( $item->get_product_id() );
			$item_variation_id = absint( $item->get_variation_id() );

			if (
				$product_id === $item_product_id ||
				$product_id === $item_variation_id ||
				( $parent_id && $parent_id === $item_product_id )
			) {
				$matches = true;
				break;
			}
		}

		return $matches ? true : $is_purchasable;
	}

	/**
	 * Runs after WooCommerce Subscriptions has rebuilt the existing order into
	 * the cart. This is the key point for Checkout Blocks: WCS has finished its
	 * native cart/session work, so save the source order addresses into the same
	 * WC customer-session snapshot that the Store API will read on /checkout/.
	 *
	 * Hook signatures differ slightly between parent and renewal setup, but both
	 * pass the WC_Order as the second argument.
	 *
	 * @param mixed    $subscriptions_or_subscription Subscription object(s).
	 * @param WC_Order $order                         Existing payment order.
	 */
	public static function after_wcs_order_setup_cart( $subscriptions_or_subscription, $order ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		if ( ! $order instanceof WC_Order || ! self::is_subscription_related_order( $order ) ) {
			return;
		}

		if ( ! self::current_customer_owns_subscription_payment_order( $order, function_exists( 'WC' ) ? WC()->customer : null ) ) {
			return;
		}

		if ( function_exists( 'WC' ) && WC()->session ) {
			WC()->session->set( self::SESSION_SUBSCRIPTION_ADDRESS, $order->get_id() );
		}

		self::copy_order_addresses_to_customer( $order );
	}

	/**
	 * Reapply the order addresses after the subscription cart is restored from
	 * session. This handles WC customer-session snapshots being rebuilt between
	 * the order-pay request and the Checkout Block's Store API request.
	 */
	public static function restore_subscription_checkout_addresses() {
		$order = self::get_subscription_address_order( function_exists( 'WC' ) ? WC()->customer : null );
		if ( $order ) {
			self::copy_order_addresses_to_customer( $order );
		}
	}

	/**
	 * Checkout Blocks serializes the shipping address by calling individual
	 * WC_Customer getters. Return the source order's stored value while the
	 * authenticated WCS payment checkout is active.
	 *
	 * @param mixed       $value    Current WC customer value.
	 * @param WC_Customer $customer Current WC customer.
	 * @return mixed
	 */
	public static function filter_subscription_checkout_shipping_value( $value, $customer ) {
		/*
		 * Checkout Blocks hydrates wc/store/cart on the initial HTML checkout request,
		 * before any later Store API customer update necessarily occurs. Therefore the
		 * source order address must be exposed both while rendering /checkout/ and on
		 * subsequent wc/store requests. Restricting this filter to REST only causes the
		 * block to hydrate from the account's saved shipping values first (often just
		 * first/last name), leaving the visible address fields blank.
		 */
		$is_checkout_page = function_exists( 'is_checkout' )
			&& is_checkout()
			&& ( ! function_exists( 'is_wc_endpoint_url' ) || ( ! is_wc_endpoint_url( 'order-pay' ) && ! is_wc_endpoint_url( 'order-received' ) ) );

		if ( ! $is_checkout_page && ! self::is_store_api_request() ) {
			return $value;
		}

		$order = self::get_subscription_address_order( $customer );
		if ( ! $order ) {
			return $value;
		}

		$field = str_replace( 'woocommerce_customer_get_shipping_', '', current_filter() );
		if ( ! in_array( $field, array( 'first_name', 'last_name', 'company', 'address_1', 'address_2', 'city', 'state', 'postcode', 'country', 'phone' ), true ) ) {
			return $value;
		}

		$shipping = self::get_order_shipping_prefill( $order );
		return array_key_exists( $field, $shipping ) ? $shipping[ $field ] : $value;
	}

	/**
	 * Checkout Blocks may POST an incomplete shipping_address immediately after
	 * loading. Because request values take precedence over the WC_Customer defaults,
	 * those empty values can wipe the order address before the cart response is
	 * returned. Reapply the source order's shipping address for that bootstrap
	 * request. Once the request contains a real street/locality value, treat it as
	 * the shopper's current address and stop forcing the original order address.
	 *
	 * @param WC_Customer     $customer Current WooCommerce customer.
	 * @param WP_REST_Request $request  Store API request.
	 */
	public static function preserve_subscription_address_during_store_api_update( $customer, $request ) {
		if ( ! $customer instanceof WC_Customer || ! $request instanceof WP_REST_Request ) {
			return;
		}

		$order = self::get_subscription_address_order( $customer );
		if ( ! $order ) {
			return;
		}

		$posted_shipping = isset( $request['shipping_address'] ) && is_array( $request['shipping_address'] )
			? $request['shipping_address']
			: array();

		/*
		 * The Checkout Block's initial customer sync can contain first/last name but
		 * blank street/city/postcode fields. Do not mistake that bootstrap request for
		 * a deliberate customer edit. A real checkout address will contain at least
		 * one of these substantive location fields.
		 */
		$has_substantive_location = false;
		foreach ( array( 'address_1', 'address_2', 'city', 'postcode' ) as $field ) {
			if ( isset( $posted_shipping[ $field ] ) && '' !== trim( (string) $posted_shipping[ $field ] ) ) {
				$has_substantive_location = true;
				break;
			}
		}

		if ( $has_substantive_location ) {
			if ( function_exists( 'WC' ) && WC()->session ) {
				WC()->session->set( self::SESSION_SUBSCRIPTION_ADDRESS, null );
			}
			return;
		}

		/*
		 * WooCommerce has already applied the incomplete Store API request to the
		 * customer object by the time this hook fires. Put the order values back now;
		 * WooCommerce saves this WC_Customer immediately after this action.
		 */
		$shipping = self::get_order_shipping_prefill( $order );
		foreach ( $shipping as $key => $value ) {
			$setter = 'set_shipping_' . $key;
			if ( is_callable( array( $customer, $setter ) ) ) {
				$customer->{$setter}( $value );
			}
		}
	}


	/**
	 * Prefill the Checkout Block's client-side cart store with the shipping
	 * address from the existing subscription payment order.
	 *
	 * WooCommerce's block checkout keeps its visible address state in the
	 * wc/store/cart data store. Server-side WC_Customer values alone can be
	 * replaced during the block's bootstrap cycle, so use WooCommerce's public
	 * setShippingAddress()/updateCustomerData() actions as the final handoff.
	 */
	public static function render_subscription_checkout_block_prefill() {
		if ( is_admin() || ! function_exists( 'is_checkout' ) || ! is_checkout() || is_wc_endpoint_url( 'order-received' ) || is_wc_endpoint_url( 'order-pay' ) ) {
			return;
		}

		$order = self::get_subscription_address_order( function_exists( 'WC' ) ? WC()->customer : null );
		if ( ! $order instanceof WC_Order ) {
			return;
		}

		$shipping = self::get_order_shipping_prefill( $order );
		if ( empty( $shipping['address_1'] ) && empty( $shipping['city'] ) && empty( $shipping['postcode'] ) ) {
			return;
		}

		$prefill = array();
		foreach ( array( 'first_name', 'last_name', 'company', 'address_1', 'address_2', 'city', 'state', 'postcode', 'country', 'phone' ) as $field ) {
			$prefill[ $field ] = isset( $shipping[ $field ] ) ? (string) $shipping[ $field ] : '';
		}

		?>
		<script id="ceg-nlp-subscription-shipping-prefill">
		(function () {
			'use strict';

			var prefill = <?php echo wp_json_encode( $prefill ); ?>;
			var attempts = 0;
			var maxAttempts = 120;
			var timer = null;

			function hasLocation(address) {
				if (!address) return false;
				return Boolean(
					(address.address_1 && String(address.address_1).trim()) ||
					(address.city && String(address.city).trim()) ||
					(address.postcode && String(address.postcode).trim()) ||
					(address.country && String(address.country).trim())
				);
			}

			function stop() {
				if (timer) {
					window.clearInterval(timer);
					timer = null;
				}
			}

			function applyPrefill() {
				attempts++;

				if (!window.wp || !window.wp.data || typeof window.wp.data.select !== 'function' || typeof window.wp.data.dispatch !== 'function') {
					if (attempts >= maxAttempts) stop();
					return;
				}

				var selector;
				var dispatcher;

				try {
					selector = window.wp.data.select('wc/store/cart');
					dispatcher = window.wp.data.dispatch('wc/store/cart');
				} catch (e) {
					if (attempts >= maxAttempts) stop();
					return;
				}

				if (!selector || !dispatcher || typeof selector.getCustomerData !== 'function' || typeof dispatcher.setShippingAddress !== 'function') {
					if (attempts >= maxAttempts) stop();
					return;
				}

				var customerData = selector.getCustomerData();
				if (!customerData) {
					if (attempts >= maxAttempts) stop();
					return;
				}

				var currentShipping = customerData.shippingAddress || {};

				/* Never overwrite a real address already present in the block. */
				if (hasLocation(currentShipping)) {
					stop();
					return;
				}

				var shippingAddress = Object.assign({}, currentShipping, prefill);

				/* WooCommerce's documented Checkout Block address action. */
				dispatcher.setShippingAddress(shippingAddress);

				/*
				 * Also send the same address through Store API so shipping calculations
				 * and the WC customer session agree with the visible block state.
				 */
				if (typeof dispatcher.updateCustomerData === 'function') {
					var latest = selector.getCustomerData() || customerData;
					var billingAddress = latest.billingAddress || {};
					try {
						var result = dispatcher.updateCustomerData({
							shippingAddress: shippingAddress,
							billingAddress: billingAddress
						}, false);
						if (result && typeof result.catch === 'function') {
							result.catch(function () {});
						}
					} catch (e) {}
				}

				stop();
			}

			/* The Checkout Block store may hydrate after footer scripts execute. */
			timer = window.setInterval(applyPrefill, 100);
			applyPrefill();
		}());
		</script>
		<?php
	}

	/**
	 * On the first Store API GET, WooCommerce reuses the pending subscription order
	 * as a draft and calls OrderController::update_order_from_cart(). That method
	 * copies shipping from WC()->customer onto the order before returning checkout
	 * data. Seed the customer from our immutable order snapshot first.
	 */
	public static function seed_subscription_shipping_before_store_api( $response, $handler, $request ) {
		if ( ! $request instanceof WP_REST_Request || 'GET' !== strtoupper( $request->get_method() ) ) {
			return $response;
		}

		$route = (string) $request->get_route();
		if ( 0 !== strpos( $route, '/wc/store/' ) || ( false === strpos( $route, '/checkout' ) && false === strpos( $route, '/cart' ) ) ) {
			return $response;
		}

		if ( ! function_exists( 'WC' ) || ! WC()->session || ! WC()->customer ) {
			return $response;
		}

		$order = self::get_subscription_address_order( WC()->customer );
		if ( ! $order instanceof WC_Order ) {
			return $response;
		}

		$shipping = self::get_order_shipping_prefill( $order );
		if ( ! self::shipping_snapshot_has_location( $shipping ) ) {
			return $response;
		}

		foreach ( $shipping as $key => $value ) {
			$setter = 'set_shipping_' . $key;
			if ( is_callable( array( WC()->customer, $setter ) ) ) {
				WC()->customer->{$setter}( $value );
			}
		}
		WC()->customer->save();

		return $response;
	}

	/**
	 * WooCommerce fires this after syncing an existing Store API draft order from
	 * the cart/customer. Restore the original order shipping in memory before the
	 * GET /checkout response is serialized. Do not save here; customer edits on
	 * later PATCH/POST requests remain authoritative.
	 */
	public static function restore_subscription_shipping_on_draft_order( $order ) {
		if ( ! $order instanceof WC_Order || 'GET' !== strtoupper( (string) ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) ) {
			return;
		}
		if ( ! self::is_store_api_request() ) {
			return;
		}

		$payment_order = self::get_subscription_address_order( function_exists( 'WC' ) ? WC()->customer : null );
		if ( ! $payment_order instanceof WC_Order || $payment_order->get_id() !== $order->get_id() ) {
			return;
		}

		$shipping = self::get_order_shipping_prefill( $payment_order );
		if ( ! self::shipping_snapshot_has_location( $shipping ) ) {
			return;
		}
		foreach ( $shipping as $key => $value ) {
			$setter = 'set_shipping_' . $key;
			if ( is_callable( array( $order, $setter ) ) ) {
				$order->{$setter}( $value );
			}
		}
	}

	/**
	 * Final safety net for Checkout Blocks. Their initial cart/checkout state comes
	 * directly from Store API JSON. Patch only GET responses for the authenticated
	 * WCS payment session so the React store receives the order shipping snapshot.
	 */
	public static function patch_subscription_shipping_in_store_api_response( $response, $server, $request ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		if ( ! $request instanceof WP_REST_Request || 'GET' !== strtoupper( $request->get_method() ) || ! $response instanceof WP_REST_Response ) {
			return $response;
		}

		$route = (string) $request->get_route();
		if ( 0 !== strpos( $route, '/wc/store/' ) || ( false === strpos( $route, '/checkout' ) && false === strpos( $route, '/cart' ) ) ) {
			return $response;
		}

		$order = self::get_subscription_address_order( function_exists( 'WC' ) ? WC()->customer : null );
		if ( ! $order instanceof WC_Order ) {
			return $response;
		}

		$shipping = self::get_order_shipping_prefill( $order );
		if ( ! self::shipping_snapshot_has_location( $shipping ) ) {
			return $response;
		}

		$data = $response->get_data();
		if ( ! is_array( $data ) ) {
			return $response;
		}

		if ( isset( $data['shipping_address'] ) ) {
			$current = is_array( $data['shipping_address'] ) ? $data['shipping_address'] : array();
			$data['shipping_address'] = array_merge( $current, $shipping );
		}

		if ( isset( $data['__experimentalCart'] ) && is_array( $data['__experimentalCart'] ) ) {
			$current = isset( $data['__experimentalCart']['shipping_address'] ) && is_array( $data['__experimentalCart']['shipping_address'] )
				? $data['__experimentalCart']['shipping_address']
				: array();
			$data['__experimentalCart']['shipping_address'] = array_merge( $current, $shipping );
		}

		$response->set_data( $data );
		return $response;
	}


	private static function get_item_variation_data( $item ) {
		$variation_id = absint( $item->get_variation_id() );
		if ( ! $variation_id ) {
			return array();
		}

		$variation = wc_get_product( $variation_id );
		if ( $variation && is_callable( array( $variation, 'get_variation_attributes' ) ) ) {
			return $variation->get_variation_attributes();
		}

		$attributes = array();
		foreach ( $item->get_meta_data() as $meta ) {
			if ( taxonomy_is_product_attribute( $meta->key ) || meta_is_product_attribute( $meta->key, $meta->value, $item->get_product_id() ) ) {
				$attributes[ 'attribute_' . sanitize_title( $meta->key ) ] = $meta->value;
			}
		}

		return $attributes;
	}

	private static function setup_regular_order_checkout( $order ) {
		if ( ! $order instanceof WC_Order || ! self::ensure_wc_cart() ) {
			wp_die(
				esc_html__( 'WooCommerce could not initialize the cart for this payment link.', 'ceg-no-login-order-payment' ),
				esc_html__( 'Unable to Prepare Checkout', 'ceg-no-login-order-payment' ),
				array( 'response' => 500 )
			);
		}

		if ( ! $order->needs_payment() ) {
			wp_safe_redirect( $order->get_checkout_order_received_url() );
			exit;
		}

		WC()->cart->empty_cart( true );
		self::copy_order_addresses_to_customer( $order );

		$added = 0;

		foreach ( $order->get_items( 'line_item' ) as $item_id => $item ) {
			if ( ! $item instanceof WC_Order_Item_Product ) {
				continue;
			}

			$product = $item->get_product();
			$quantity = (int) $item->get_quantity();

			if ( ! $product || $quantity < 1 ) {
				WC()->cart->empty_cart( true );
				wp_die(
					sprintf(
						/* translators: %s: order item name */
						esc_html__( 'The product "%s" can no longer be added to Checkout. Use the standard order payment page for this order.', 'ceg-no-login-order-payment' ),
						esc_html( $item->get_name() )
					),
					esc_html__( 'Unable to Rebuild Order', 'ceg-no-login-order-payment' ),
					array( 'response' => 409 )
				);
			}

			$product_id   = absint( $item->get_product_id() );
			$variation_id = absint( $item->get_variation_id() );
			$unit_price   = (float) $item->get_total() / $quantity;

			$cart_item_data = array(
				'ceg_nlp_regular_payment' => array(
					'order_id'     => $order->get_id(),
					'line_item_id' => $item_id,
					'unit_price'   => wc_format_decimal( $unit_price, wc_get_price_decimals() + 4 ),
				),
			);

			$cart_item_data = apply_filters( 'woocommerce_order_again_cart_item_data', $cart_item_data, $item, $order );

			$cart_item_key = WC()->cart->add_to_cart(
				$product_id,
				$quantity,
				$variation_id,
				self::get_item_variation_data( $item ),
				$cart_item_data
			);

			if ( ! $cart_item_key ) {
				WC()->cart->empty_cart( true );
				wp_die(
					sprintf(
						/* translators: %s: order item name */
						esc_html__( 'The product "%s" could not be restored to Checkout.', 'ceg-no-login-order-payment' ),
						esc_html( $item->get_name() )
					),
					esc_html__( 'Unable to Rebuild Order', 'ceg-no-login-order-payment' ),
					array( 'response' => 409 )
				);
			}

			$added++;
		}

		if ( ! $added ) {
			wp_die(
				esc_html__( 'This order has no purchasable product line items to send through Checkout.', 'ceg-no-login-order-payment' ),
				esc_html__( 'Unable to Rebuild Order', 'ceg-no-login-order-payment' ),
				array( 'response' => 409 )
			);
		}

		WC()->session->set( self::SESSION_REGULAR, $order->get_id() );
		WC()->session->set( 'order_awaiting_payment', $order->get_id() );
		WC()->session->set( 'store_api_draft_order', $order->get_id() );

		self::set_original_shipping_method( $order );

		WC()->cart->calculate_totals();

		$order->set_cart_hash( WC()->cart->get_cart_hash() );
		$order->save();

		if ( is_callable( array( WC()->cart, 'set_session' ) ) ) {
			WC()->cart->set_session();
		}

		if ( is_callable( array( WC()->session, 'set_customer_session_cookie' ) ) ) {
			WC()->session->set_customer_session_cookie( true );
		}

		wp_safe_redirect( wc_get_checkout_url() );
		exit;
	}

	private static function set_original_shipping_method( $order ) {
		if ( ! $order instanceof WC_Order || ! function_exists( 'WC' ) || ! WC()->session ) {
			return;
		}

		$chosen = array();
		foreach ( $order->get_items( 'shipping' ) as $shipping_item ) {
			$method_id   = $shipping_item->get_method_id();
			$instance_id = absint( $shipping_item->get_instance_id() );
			if ( $method_id ) {
				$chosen[] = $instance_id ? $method_id . ':' . $instance_id : $method_id;
			}
		}

		if ( $chosen ) {
			WC()->session->set( 'chosen_shipping_methods', $chosen );
		}
	}

	private static function get_regular_checkout_order_id() {
		if ( ! function_exists( 'WC' ) || ! WC()->session ) {
			return 0;
		}

		$order_id = absint( WC()->session->get( self::SESSION_REGULAR, 0 ) );
		if ( ! $order_id || ! self::session_has_valid_magic_link( $order_id ) ) {
			return 0;
		}

		return $order_id;
	}

	public static function apply_regular_order_prices( $cart ) {
		$order_id = self::get_regular_checkout_order_id();
		if ( ! $order_id || ! $cart instanceof WC_Cart ) {
			return;
		}

		foreach ( $cart->get_cart() as $cart_item ) {
			if (
				empty( $cart_item['ceg_nlp_regular_payment'] ) ||
				absint( $cart_item['ceg_nlp_regular_payment']['order_id'] ?? 0 ) !== $order_id ||
				empty( $cart_item['data'] ) ||
				! is_object( $cart_item['data'] ) ||
				! is_callable( array( $cart_item['data'], 'set_price' ) )
			) {
				continue;
			}

			$price = isset( $cart_item['ceg_nlp_regular_payment']['unit_price'] )
				? (float) $cart_item['ceg_nlp_regular_payment']['unit_price']
				: null;

			if ( null !== $price ) {
				$cart_item['data']->set_price( $price );
			}
		}
	}

	public static function apply_regular_order_fees( $cart ) {
		$order_id = self::get_regular_checkout_order_id();
		if ( ! $order_id || ! $cart instanceof WC_Cart ) {
			return;
		}

		$order = wc_get_order( $order_id );
		if ( ! $order ) {
			return;
		}

		foreach ( $order->get_items( 'fee' ) as $fee ) {
			$cart->add_fee(
				$fee->get_name(),
				(float) $fee->get_total(),
				(float) $fee->get_total_tax() !== 0.0,
				$fee->get_tax_class()
			);
		}
	}

	public static function restore_regular_order_checkout_session( $cart ) {
		$order_id = self::get_regular_checkout_order_id();
		if ( ! $order_id || ! $cart instanceof WC_Cart ) {
			return;
		}

		$found = false;
		foreach ( $cart->get_cart() as $cart_item ) {
			if ( ! empty( $cart_item['ceg_nlp_regular_payment']['order_id'] ) && absint( $cart_item['ceg_nlp_regular_payment']['order_id'] ) === $order_id ) {
				$found = true;
				break;
			}
		}

		if ( $found ) {
			WC()->session->set( 'order_awaiting_payment', $order_id );
			WC()->session->set( 'store_api_draft_order', $order_id );
		}
	}

	public static function refresh_regular_order_cart_hash_for_classic_checkout( $created_order_id, $checkout ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$order_id = self::get_regular_checkout_order_id();
		if ( $order_id && function_exists( 'WC' ) && WC()->cart ) {
			$order = wc_get_order( $order_id );
			if ( $order ) {
				$order->set_cart_hash( WC()->cart->get_cart_hash() );
				$order->save();
			}
		}

		return $created_order_id;
	}

	public static function support_regular_order_resume_status( $has_status, $order, $status ) {
		if ( $has_status || ! $order instanceof WC_Order ) {
			return $has_status;
		}

		/*
		 * WooCommerce Subscriptions hard-codes pending/failed when deciding whether
		 * an existing initial-payment or renewal order should be rebuilt into the cart.
		 * Core/Store API retry logic is based on the same pending/failed concept.
		 *
		 * For an exact, valid magic-link authorization, let an unpaid On hold order
		 * satisfy that status check without changing the order's real status. This is
		 * what allows both regular and subscription On hold orders to enter the normal
		 * Checkout flow. The authorization is still tied to this exact order/customer.
		 */
		if (
			'on-hold' === $order->get_status() &&
			is_array( $status ) &&
			array_intersect( array( 'pending', 'failed' ), $status ) &&
			self::has_valid_magic_authorization( $order->get_id() )
		) {
			return true;
		}

		$order_id = self::get_regular_checkout_order_id();
		if ( ! $order_id || $order->get_id() !== $order_id ) {
			return $has_status;
		}

		/*
		 * Checkout Block asks whether the existing order is checkout-draft before it
		 * evaluates its pending/failed retry path. Refresh the cart hash on that check
		 * so legitimate Checkout recalculations do not create a new order.
		 */
		if ( 'checkout-draft' === $status && function_exists( 'WC' ) && WC()->cart ) {
			$order->set_cart_hash( WC()->cart->get_cart_hash() );
			$order->save();
			return $has_status;
		}

		return $has_status;
	}

	public static function allow_magic_link_payment( $allcaps, $caps, $args, $user ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( empty( $caps[0] ) || 'pay_for_order' !== $caps[0] ) {
			return $allcaps;
		}

		$order_id = isset( $args[2] ) ? absint( $args[2] ) : 0;
		if ( $order_id && self::has_valid_magic_authorization( $order_id ) ) {
			$allcaps['pay_for_order'] = true;
		}

		return $allcaps;
	}

	public static function skip_email_verification_for_magic_link( $required, $order, $context ) {
		if (
			'order-pay' === $context &&
			$order instanceof WC_Order &&
			self::has_valid_magic_authorization( $order->get_id() )
		) {
			return false;
		}

		return $required;
	}

	public static function allow_on_hold_for_magic_link( $statuses, $order ) {
		if (
			$order instanceof WC_Order &&
			$order->has_status( 'on-hold' ) &&
			$order->get_total() > 0 &&
			self::has_valid_magic_authorization( $order->get_id() )
		) {
			$statuses[] = 'on-hold';
		}

		return array_values( array_unique( $statuses ) );
	}

	public static function revoke_link_after_payment( $order_id ) {
		$order = wc_get_order( $order_id );
		if ( ! $order ) {
			return;
		}

		$order->delete_meta_data( self::META_NONCE );
		$order->delete_meta_data( self::META_EXPIRES );
		$order->save();

		if ( function_exists( 'WC' ) && WC()->session ) {
			$auth = WC()->session->get( self::SESSION_AUTH, array() );
			if ( is_array( $auth ) && isset( $auth['order_id'] ) && absint( $auth['order_id'] ) === absint( $order_id ) ) {
				WC()->session->set( self::SESSION_AUTH, null );
			}

			if ( absint( WC()->session->get( self::SESSION_REGULAR, 0 ) ) === absint( $order_id ) ) {
				WC()->session->set( self::SESSION_REGULAR, null );
			}

			if ( absint( WC()->session->get( self::SESSION_SUBSCRIPTION_ADDRESS, 0 ) ) === absint( $order_id ) ) {
				WC()->session->set( self::SESSION_SUBSCRIPTION_ADDRESS, null );
			}

			$shipping_snapshot = WC()->session->get( self::SESSION_SUBSCRIPTION_SHIPPING, array() );
			if ( is_array( $shipping_snapshot ) && absint( $shipping_snapshot['order_id'] ?? 0 ) === absint( $order_id ) ) {
				WC()->session->set( self::SESSION_SUBSCRIPTION_SHIPPING, null );
			}
		}
	}
}

add_action( 'plugins_loaded', array( 'CEG_No_Login_Order_Payment_Links', 'init' ), 20 );
