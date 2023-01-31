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

// NewListZonesParams creates a new ListZonesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListZonesParams() *ListZonesParams {
	return &ListZonesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListZonesParamsWithTimeout creates a new ListZonesParams object
// with the ability to set a timeout on a request.
func NewListZonesParamsWithTimeout(timeout time.Duration) *ListZonesParams {
	return &ListZonesParams{
		timeout: timeout,
	}
}

// NewListZonesParamsWithContext creates a new ListZonesParams object
// with the ability to set a context for a request.
func NewListZonesParamsWithContext(ctx context.Context) *ListZonesParams {
	return &ListZonesParams{
		Context: ctx,
	}
}

// NewListZonesParamsWithHTTPClient creates a new ListZonesParams object
// with the ability to set a custom HTTPClient for a request.
func NewListZonesParamsWithHTTPClient(client *http.Client) *ListZonesParams {
	return &ListZonesParams{
		HTTPClient: client,
	}
}

/*
ListZonesParams contains all the parameters to send to the API endpoint

	for the list zones operation.

	Typically these are written to a http.Request.
*/
type ListZonesParams struct {

	/* Limit.

	   Limits the number of objects in the output. (default value: 100, maximum value: 500).

	   Format: int32
	   Default: 100
	*/
	Limit *int32

	/* NamePattern.

	   DNS zone name pattern. Wildcard (*) can be used.
	*/
	NamePattern *string

	/* Offset.

	   Used to retrieve all objects from a certain offset up to the. (default value: 0).

	   Format: int32
	*/
	Offset *int32

	/* OrderByCreationDate.

	   Sorting type (asc/desc).

	   Default: "desc"
	*/
	OrderByCreationDate *string

	/* OrderByModificationDate.

	   Sorting type (asc/desc).
	*/
	OrderByModificationDate *string

	/* OrderByName.

	   Sorting type (asc/desc).
	*/
	OrderByName *string

	/* Provider.

	   Name of the DNS provider. Set provider=sectigo in case of only sectigo premium DNS zone should be retrieved.
	*/
	Provider *string

	/* Type.

	   DNS zone type (master or slave).
	*/
	Type *string

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

// WithDefaults hydrates default values in the list zones params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListZonesParams) WithDefaults() *ListZonesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the list zones params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListZonesParams) SetDefaults() {
	var (
		limitDefault = int32(100)

		orderByCreationDateDefault = string("desc")
	)

	val := ListZonesParams{
		Limit:               &limitDefault,
		OrderByCreationDate: &orderByCreationDateDefault,
	}

	val.timeout = o.timeout
	val.Context = o.Context
	val.HTTPClient = o.HTTPClient
	*o = val
}

// WithTimeout adds the timeout to the list zones params
func (o *ListZonesParams) WithTimeout(timeout time.Duration) *ListZonesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the list zones params
func (o *ListZonesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the list zones params
func (o *ListZonesParams) WithContext(ctx context.Context) *ListZonesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the list zones params
func (o *ListZonesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the list zones params
func (o *ListZonesParams) WithHTTPClient(client *http.Client) *ListZonesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the list zones params
func (o *ListZonesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLimit adds the limit to the list zones params
func (o *ListZonesParams) WithLimit(limit *int32) *ListZonesParams {
	o.SetLimit(limit)
	return o
}

// SetLimit adds the limit to the list zones params
func (o *ListZonesParams) SetLimit(limit *int32) {
	o.Limit = limit
}

// WithNamePattern adds the namePattern to the list zones params
func (o *ListZonesParams) WithNamePattern(namePattern *string) *ListZonesParams {
	o.SetNamePattern(namePattern)
	return o
}

// SetNamePattern adds the namePattern to the list zones params
func (o *ListZonesParams) SetNamePattern(namePattern *string) {
	o.NamePattern = namePattern
}

// WithOffset adds the offset to the list zones params
func (o *ListZonesParams) WithOffset(offset *int32) *ListZonesParams {
	o.SetOffset(offset)
	return o
}

// SetOffset adds the offset to the list zones params
func (o *ListZonesParams) SetOffset(offset *int32) {
	o.Offset = offset
}

// WithOrderByCreationDate adds the orderByCreationDate to the list zones params
func (o *ListZonesParams) WithOrderByCreationDate(orderByCreationDate *string) *ListZonesParams {
	o.SetOrderByCreationDate(orderByCreationDate)
	return o
}

// SetOrderByCreationDate adds the orderByCreationDate to the list zones params
func (o *ListZonesParams) SetOrderByCreationDate(orderByCreationDate *string) {
	o.OrderByCreationDate = orderByCreationDate
}

// WithOrderByModificationDate adds the orderByModificationDate to the list zones params
func (o *ListZonesParams) WithOrderByModificationDate(orderByModificationDate *string) *ListZonesParams {
	o.SetOrderByModificationDate(orderByModificationDate)
	return o
}

// SetOrderByModificationDate adds the orderByModificationDate to the list zones params
func (o *ListZonesParams) SetOrderByModificationDate(orderByModificationDate *string) {
	o.OrderByModificationDate = orderByModificationDate
}

// WithOrderByName adds the orderByName to the list zones params
func (o *ListZonesParams) WithOrderByName(orderByName *string) *ListZonesParams {
	o.SetOrderByName(orderByName)
	return o
}

// SetOrderByName adds the orderByName to the list zones params
func (o *ListZonesParams) SetOrderByName(orderByName *string) {
	o.OrderByName = orderByName
}

// WithProvider adds the provider to the list zones params
func (o *ListZonesParams) WithProvider(provider *string) *ListZonesParams {
	o.SetProvider(provider)
	return o
}

// SetProvider adds the provider to the list zones params
func (o *ListZonesParams) SetProvider(provider *string) {
	o.Provider = provider
}

// WithType adds the typeVar to the list zones params
func (o *ListZonesParams) WithType(typeVar *string) *ListZonesParams {
	o.SetType(typeVar)
	return o
}

// SetType adds the type to the list zones params
func (o *ListZonesParams) SetType(typeVar *string) {
	o.Type = typeVar
}

// WithWithDnskey adds the withDnskey to the list zones params
func (o *ListZonesParams) WithWithDnskey(withDnskey *bool) *ListZonesParams {
	o.SetWithDnskey(withDnskey)
	return o
}

// SetWithDnskey adds the withDnskey to the list zones params
func (o *ListZonesParams) SetWithDnskey(withDnskey *bool) {
	o.WithDnskey = withDnskey
}

// WithWithHistory adds the withHistory to the list zones params
func (o *ListZonesParams) WithWithHistory(withHistory *bool) *ListZonesParams {
	o.SetWithHistory(withHistory)
	return o
}

// SetWithHistory adds the withHistory to the list zones params
func (o *ListZonesParams) SetWithHistory(withHistory *bool) {
	o.WithHistory = withHistory
}

// WithWithRecords adds the withRecords to the list zones params
func (o *ListZonesParams) WithWithRecords(withRecords *bool) *ListZonesParams {
	o.SetWithRecords(withRecords)
	return o
}

// SetWithRecords adds the withRecords to the list zones params
func (o *ListZonesParams) SetWithRecords(withRecords *bool) {
	o.WithRecords = withRecords
}

// WriteToRequest writes these params to a swagger request
func (o *ListZonesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Limit != nil {

		// query param limit
		var qrLimit int32

		if o.Limit != nil {
			qrLimit = *o.Limit
		}
		qLimit := swag.FormatInt32(qrLimit)
		if qLimit != "" {

			if err := r.SetQueryParam("limit", qLimit); err != nil {
				return err
			}
		}
	}

	if o.NamePattern != nil {

		// query param name_pattern
		var qrNamePattern string

		if o.NamePattern != nil {
			qrNamePattern = *o.NamePattern
		}
		qNamePattern := qrNamePattern
		if qNamePattern != "" {

			if err := r.SetQueryParam("name_pattern", qNamePattern); err != nil {
				return err
			}
		}
	}

	if o.Offset != nil {

		// query param offset
		var qrOffset int32

		if o.Offset != nil {
			qrOffset = *o.Offset
		}
		qOffset := swag.FormatInt32(qrOffset)
		if qOffset != "" {

			if err := r.SetQueryParam("offset", qOffset); err != nil {
				return err
			}
		}
	}

	if o.OrderByCreationDate != nil {

		// query param order_by.creation_date
		var qrOrderByCreationDate string

		if o.OrderByCreationDate != nil {
			qrOrderByCreationDate = *o.OrderByCreationDate
		}
		qOrderByCreationDate := qrOrderByCreationDate
		if qOrderByCreationDate != "" {

			if err := r.SetQueryParam("order_by.creation_date", qOrderByCreationDate); err != nil {
				return err
			}
		}
	}

	if o.OrderByModificationDate != nil {

		// query param order_by.modification_date
		var qrOrderByModificationDate string

		if o.OrderByModificationDate != nil {
			qrOrderByModificationDate = *o.OrderByModificationDate
		}
		qOrderByModificationDate := qrOrderByModificationDate
		if qOrderByModificationDate != "" {

			if err := r.SetQueryParam("order_by.modification_date", qOrderByModificationDate); err != nil {
				return err
			}
		}
	}

	if o.OrderByName != nil {

		// query param order_by.name
		var qrOrderByName string

		if o.OrderByName != nil {
			qrOrderByName = *o.OrderByName
		}
		qOrderByName := qrOrderByName
		if qOrderByName != "" {

			if err := r.SetQueryParam("order_by.name", qOrderByName); err != nil {
				return err
			}
		}
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

	if o.Type != nil {

		// query param type
		var qrType string

		if o.Type != nil {
			qrType = *o.Type
		}
		qType := qrType
		if qType != "" {

			if err := r.SetQueryParam("type", qType); err != nil {
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