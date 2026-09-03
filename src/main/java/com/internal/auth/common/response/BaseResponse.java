package com.internal.auth.common.response;

import lombok.Data;

@Data
public class BaseResponse {

	private int statusCode;

	private String description;

	private Object data;

	private Object errors;

	public BaseResponse() {
	}

	public BaseResponse(int statusCode, String description) {
		super();
		this.statusCode = statusCode;
		this.description = description;
	}

	public BaseResponse(int statusCode) {
		super();
		this.statusCode = statusCode;
	}

	public BaseResponse(int statusCode, String description, Object data) {
		this.statusCode = statusCode;
		this.description = description;
		this.data = data;
	}
}