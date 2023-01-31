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

	"wukl.net/projects/cert-manager-webhook-openprovider/opapi/models"
)

// NewUpdateZoneParams creates a new UpdateZoneParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpdateZoneParams() *UpdateZoneParams {
	return &UpdateZoneParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpdateZoneParamsWithTimeout creates a new UpdateZoneParams object
// with the ability to set a timeout on a request.
func NewUpdateZoneParamsWithTimeout(timeout time.Duration) *UpdateZoneParams {
	return &UpdateZoneParams{
		timeout: timeout,
	}
}

// NewUpdateZoneParamsWithContext creates a new UpdateZoneParams object
// with the ability to set a context for a request.
func NewUpdateZoneParamsWithContext(ctx context.Context) *UpdateZoneParams {
	return &UpdateZoneParams{
		Context: ctx,
	}
}

// NewUpdateZoneParamsWithHTTPClient creates a new UpdateZoneParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpdateZoneParamsWithHTTPClient(client *http.Client) *UpdateZoneParams {
	return &UpdateZoneParams{
		HTTPClient: client,
	}
}

/*
UpdateZoneParams contains all the parameters to send to the API endpoint

	for the update zone operation.

	Typically these are written to a http.Request.
*/
type UpdateZoneParams struct {

	// Body.
	Body *models.ZoneUpdateZoneRequest

	/* Name.

	   Name of the domain to which DNS zone corresponds
	*/
	Name string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the update zone params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateZoneParams) WithDefaults() *UpdateZoneParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the update zone params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpdateZoneParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the update zone params
func (o *UpdateZoneParams) WithTimeout(timeout time.Duration) *UpdateZoneParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the update zone params
func (o *UpdateZoneParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the update zone params
func (o *UpdateZoneParams) WithContext(ctx context.Context) *UpdateZoneParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the update zone params
func (o *UpdateZoneParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the update zone params
func (o *UpdateZoneParams) WithHTTPClient(client *http.Client) *UpdateZoneParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the update zone params
func (o *UpdateZoneParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the update zone params
func (o *UpdateZoneParams) WithBody(body *models.ZoneUpdateZoneRequest) *UpdateZoneParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the update zone params
func (o *UpdateZoneParams) SetBody(body *models.ZoneUpdateZoneRequest) {
	o.Body = body
}

// WithName adds the name to the update zone params
func (o *UpdateZoneParams) WithName(name string) *UpdateZoneParams {
	o.SetName(name)
	return o
}

// SetName adds the name to the update zone params
func (o *UpdateZoneParams) SetName(name string) {
	o.Name = name
}

// WriteToRequest writes these params to a swagger request
func (o *UpdateZoneParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	// path param name
	if err := r.SetPathParam("name", o.Name); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}