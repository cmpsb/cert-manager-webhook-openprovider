// Code generated by go-swagger; DO NOT EDIT.

package zone_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// NewGetZoneParams creates a new GetZoneParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetZoneParams() *GetZoneParams {
	return &GetZoneParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetZoneParamsWithTimeout creates a new GetZoneParams object
// with the ability to set a timeout on a request.
func NewGetZoneParamsWithTimeout(timeout time.Duration) *GetZoneParams {
	return &GetZoneParams{
		timeout: timeout,
	}
}

// NewGetZoneParamsWithContext creates a new GetZoneParams object
// with the ability to set a context for a request.
func NewGetZoneParamsWithContext(ctx context.Context) *GetZoneParams {
	return &GetZoneParams{
		Context: ctx,
	}
}

// NewGetZoneParamsWithHTTPClient creates a new GetZoneParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetZoneParamsWithHTTPClient(client *http.Client) *GetZoneParams {
	return &GetZoneParams{
		HTTPClient: client,
	}
}

/*
GetZoneParams contains all the parameters to send to the API endpoint

	for the get zone operation.

	Typically these are written to a http.Request.
*/
type GetZoneParams struct {

	/* ID.

	   DNS zone ID.
	*/
	ID *string

	/* Name.

	   Name of the domain to which DNS zone corresponds
	*/
	Name string

	/* Provider.

	   Name of the DNS provider. Set provider=sectigo in case of only sectigo premium DNS zone should be retrieved.
	*/
	Provider *string

	/* WithDnskey.

	   Indicates, whether DNSSEC keys should be displayed in output.

	   Format: boolean
	*/
	WithDnskey *bool

	/* WithHistory.

	   Indicates, whether DNS zone history should be displayed in output.

	   Format: boolean
	*/
	WithHistory *bool

	/* WithRecords.

	   Indicates, whether DNS records should be displayed in output.

	   Format: boolean
	*/
	WithRecords *bool

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get zone params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetZoneParams) WithDefaults() *GetZoneParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get zone params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetZoneParams) SetDefaults() {
	var (
		withHistoryDefault = bool(false)

		withRecordsDefault = bool(false)
	)

	val := GetZoneParams{
		WithHistory: &withHistoryDefault,
		WithRecords: &withRecordsDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the get zone params
func (o *GetZoneParams) WithTimeout(timeout time.Duration) *GetZoneParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get zone params
func (o *GetZoneParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get zone params
func (o *GetZoneParams) WithContext(ctx context.Context) *GetZoneParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get zone params
func (o *GetZoneParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get zone params
func (o *GetZoneParams) WithHTTPClient(client *http.Client) *GetZoneParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get zone params
func (o *GetZoneParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the get zone params
func (o *GetZoneParams) WithID(id *string) *GetZoneParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the get zone params
func (o *GetZoneParams) SetID(id *string) {
	o.ID = id
}

// WithName adds the name to the get zone params
func (o *GetZoneParams) WithName(name string) *GetZoneParams {
	o.SetName(name)
	return o
}

// SetName adds the name to the get zone params
func (o *GetZoneParams) SetName(name string) {
	o.Name = name
}

// WithProvider adds the provider to the get zone params
func (o *GetZoneParams) WithProvider(provider *string) *GetZoneParams {
	o.SetProvider(provider)
	return o
}

// SetProvider adds the provider to the get zone params
func (o *GetZoneParams) SetProvider(provider *string) {
	o.Provider = provider
}

// WithWithDnskey adds the withDnskey to the get zone params
func (o *GetZoneParams) WithWithDnskey(withDnskey *bool) *GetZoneParams {
	o.SetWithDnskey(withDnskey)
	return o
}

// SetWithDnskey adds the withDnskey to the get zone params
func (o *GetZoneParams) SetWithDnskey(withDnskey *bool) {
	o.WithDnskey = withDnskey
}

// WithWithHistory adds the withHistory to the get zone params
func (o *GetZoneParams) WithWithHistory(withHistory *bool) *GetZoneParams {
	o.SetWithHistory(withHistory)
	return o
}

// SetWithHistory adds the withHistory to the get zone params
func (o *GetZoneParams) SetWithHistory(withHistory *bool) {
	o.WithHistory = withHistory
}

// WithWithRecords adds the withRecords to the get zone params
func (o *GetZoneParams) WithWithRecords(withRecords *bool) *GetZoneParams {
	o.SetWithRecords(withRecords)
	return o
}

// SetWithRecords adds the withRecords to the get zone params
func (o *GetZoneParams) SetWithRecords(withRecords *bool) {
	o.WithRecords = withRecords
}

// WriteToRequest writes these params to a swagger request
func (o *GetZoneParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.ID != nil {

		// query param id
		var qrID string

		if o.ID != nil {
			qrID = *o.ID
		}
		qID := qrID
		if qID != "" {

			if err := r.SetQueryParam("id", qID); err != nil {
				return err
			}
		}
	}

	// path param name
	if err := r.SetPathParam("name", o.Name); err != nil {
		return err
	}

	if o.Provider != nil {

		// query param provider
		var qrProvider string

		if o.Provider != nil {
			qrProvider = *o.Provider
		}
		qProvider := qrProvider
		if qProvider != "" {

			if err := r.SetQueryParam("provider", qProvider); err != nil {
				return err
			}
		}
	}

	if o.WithDnskey != nil {

		// query param with_dnskey
		var qrWithDnskey bool

		if o.WithDnskey != nil {
			qrWithDnskey = *o.WithDnskey
		}
		qWithDnskey := swag.FormatBool(qrWithDnskey)
		if qWithDnskey != "" {

			if err := r.SetQueryParam("with_dnskey", qWithDnskey); err != nil {
				return err
			}
		}
	}

	if o.WithHistory != nil {

		// query param with_history
		var qrWithHistory bool

		if o.WithHistory != nil {
			qrWithHistory = *o.WithHistory
		}
		qWithHistory := swag.FormatBool(qrWithHistory)
		if qWithHistory != "" {

			if err := r.SetQueryParam("with_history", qWithHistory); err != nil {
				return err
			}
		}
	}

	if o.WithRecords != nil {

		// query param with_records
		var qrWithRecords bool

		if o.WithRecords != nil {
			qrWithRecords = *o.WithRecords
		}
		qWithRecords := swag.FormatBool(qrWithRecords)
		if qWithRecords != "" {

			if err := r.SetQueryParam("with_records", qWithRecords); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
